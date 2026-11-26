"""HTTP API. Thin wrapper over Engine: authentication, limits, error mapping."""
from __future__ import annotations

import hashlib
import hmac
import re
import time
import uuid
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app import __version__
from app.config import Settings, load_settings
from app.db import Database, QuotaExceeded
from app.engine import ActionNotFound, Engine, GuardBlocked, ModelUnavailable
from app.llm import get_provider
from app.ratelimit import RateLimiter
from app.retrieval import HashingEmbedder
from app.telemetry import Telemetry

_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ID = re.compile(r"^[0-9a-f-]{36}$")


class AskIn(BaseModel):
    question: str = Field(min_length=3, max_length=3000)


class DocumentIn(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    content: str = Field(min_length=1, max_length=50_000)


class BodyLimit:
    """Pure-ASGI body cap that also counts chunked bodies (Content-Length alone is not enough).
    FastAPI converts body-read errors into a 400, so when the cap trips we override whatever
    response the application produces with a 413."""

    BODY = b'{"detail":"Request body too large"}'

    def __init__(self, app, max_bytes: int) -> None:
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope["headers"]).get(b"content-length")
        if declared and declared.isdigit() and int(declared) > self.max_bytes:
            await self._start(send)
            return await send({"type": "http.response.body", "body": self.BODY})
        seen, tripped, started = 0, False, False

        async def limited():
            nonlocal seen, tripped
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_bytes:
                    tripped = True
                    raise _TooLarge()
            return message

        async def guarded_send(message):
            nonlocal started
            if not tripped:
                started = started or message["type"] == "http.response.start"
                return await send(message)
            if message["type"] == "http.response.start":
                started = True
                return await self._start(send)
            if message["type"] == "http.response.body" and not message.get("more_body"):
                return await send({"type": "http.response.body", "body": self.BODY})

        try:
            await self.app(scope, limited, guarded_send)
        except _TooLarge:
            if not started:
                await self._start(send)
                await send({"type": "http.response.body", "body": self.BODY})

    async def _start(self, send) -> None:
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(self.BODY)).encode())]})


class _TooLarge(Exception):
    pass


def create_app(settings: Settings | None = None, provider=None, telemetry: Telemetry | None = None) -> FastAPI:
    settings = settings or load_settings()
    db = Database(settings.db_path, max_docs_per_tenant=settings.max_docs_per_tenant)
    tel = telemetry or Telemetry(settings.log_path, max_bytes=settings.log_max_bytes,
                                 backups=settings.log_backups, mode=settings.mode_label)
    engine = Engine(settings, db, provider or get_provider(settings), tel, HashingEmbedder())
    ask_limiter = RateLimiter(settings.ask_rate_per_min)
    fail_limiter = RateLimiter(settings.auth_fail_per_min)
    last_emit: dict[str, float] = {}

    app = FastAPI(title="AegisRAG", version=__version__, docs_url=None, redoc_url=None)
    app.add_middleware(BodyLimit, max_bytes=settings.max_body_bytes)
    app.state.engine, app.state.db, app.state.settings, app.state.telemetry = engine, db, settings, tel
    db.init()

    def once_per(key: str, seconds: float = 60.0) -> bool:
        now = time.monotonic()
        if now - last_emit.get(key, -1e9) >= seconds:
            last_emit[key] = now
            return True
        return False

    def client_id(request: Request) -> str:
        host = request.client.host if request.client else "unknown"
        return hashlib.sha256(host.encode()).hexdigest()[:12]

    def current_user(request: Request) -> dict[str, str]:
        cid = client_id(request)
        if not fail_limiter.peek(cid):  # locked out: do not even evaluate the token
            if once_per(f"burst:{cid}"):
                tel.emit("auth_failed_burst", "high", client=cid)
            raise HTTPException(429, "Too many failed authentication attempts")
        header = request.headers.get("authorization", "")
        token = header[7:].strip() if header.lower().startswith("bearer ") else ""
        digest = hashlib.sha256(token.encode()).hexdigest()
        for stored, user in settings.users.items():
            if hmac.compare_digest(stored, digest):
                return user
        fail_limiter.allow(cid)
        tel.emit("auth_failed", "medium", client=cid, has_token=bool(token))
        raise HTTPException(401, "Invalid or missing bearer token")

    @app.middleware("http")
    async def add_headers(request: Request, call_next):
        request.state.request_id = str(uuid.uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(GuardBlocked)
    async def _blocked(request: Request, exc: GuardBlocked):
        return JSONResponse({"detail": "Request blocked by the input guard", "request_id": exc.request_id}, 400)

    @app.exception_handler(ModelUnavailable)
    async def _model(request: Request, exc: ModelUnavailable):
        return JSONResponse({"detail": "The language model is unavailable", "request_id": exc.request_id}, 502)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "version": __version__, "mode": settings.mode_label, "llm_provider": settings.llm_provider}

    @app.post("/documents", status_code=201)
    def add_document(body: DocumentIn, request: Request, user: dict[str, str] = Depends(current_user)):
        title = _CTRL.sub("", body.title).strip() or "untitled"
        try:
            doc_id = engine.ingest(user, title, body.content, request.state.request_id)
        except QuotaExceeded:
            raise HTTPException(429, "Document quota reached")
        return {"id": doc_id, "title": title, "tenant_id": user["tenant_id"]}

    @app.get("/documents")
    def list_documents(user: dict[str, str] = Depends(current_user)):
        return {"documents": db.list_documents(user["tenant_id"])}

    @app.post("/ask")
    def ask(body: AskIn, request: Request, user: dict[str, str] = Depends(current_user)):
        if not ask_limiter.allow(user["user_id"]):
            if once_per(f"rl:{user['user_id']}"):
                tel.emit("rate_limited", "low", user=user, scope="ask")
            raise HTTPException(429, "Rate limit exceeded")
        r = engine.ask(user, body.question, request.state.request_id)
        return {"answer": r.answer, "sources": r.sources, "tool_trace": r.tool_trace,
                "security": {"controls": r.controls, "quarantined_chunks": r.quarantined, "redactions": r.redactions,
                             "cached": r.cached},
                "request_id": r.request_id}

    @app.get("/approvals")
    def approvals(user: dict[str, str] = Depends(current_user)):
        return {"pending": db.list_actions(user["tenant_id"], "pending_approval")}

    @app.post("/approvals/{action_id}/approve")
    def approve(action_id: str, user: dict[str, str] = Depends(current_user)):
        if not _ID.match(action_id):
            raise HTTPException(404, "Not found")
        try:
            return engine.approve(user, action_id)
        except ActionNotFound:
            raise HTTPException(404, "Not found")

    @app.post("/approvals/{action_id}/reject")
    def reject(action_id: str, user: dict[str, str] = Depends(current_user)):
        if not _ID.match(action_id):
            raise HTTPException(404, "Not found")
        try:
            return engine.reject(user, action_id)
        except ActionNotFound:
            raise HTTPException(404, "Not found")

    return app


def __getattr__(name: str):  # lazy module-level `app` so importing the module has no side effects
    if name == "app":
        global _APP
        try:
            return _APP
        except NameError:
            _APP = create_app()
            return _APP
    raise AttributeError(name)
