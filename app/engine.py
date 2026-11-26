"""The request pipeline. Every security decision is made here, in one readable place,
and every decision emits telemetry (detection runs even when prevention is off)."""
from __future__ import annotations

import re
import secrets
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

import hashlib

from app import guard, policy, prompts, redact, retrieval, textnorm, tools
from app.config import Settings
from app.db import Database
from app.llm import ModelError, ModelRequest
from app.telemetry import Telemetry, digest

User = dict[str, str]
CACHE_MAX = 256
OBS_MAX = 1500


class GuardBlocked(Exception):
    def __init__(self, request_id: str) -> None:
        super().__init__("blocked by input guard")
        self.request_id = request_id


class ModelUnavailable(Exception):
    def __init__(self, request_id: str) -> None:
        super().__init__("model unavailable")
        self.request_id = request_id


class ActionNotFound(Exception):
    pass


@dataclass
class AskResult:
    answer: str
    sources: list[str]
    controls: list[str]
    tool_trace: list[dict[str, Any]]
    quarantined: int
    redactions: dict[str, int]
    request_id: str
    cached: bool = False
    raw_answer: str = field(default="", repr=False)


# ------------------------------------------------------------------ output URL handling
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+", re.I)
_MD_IMG = re.compile(r"!\[[^\]]*\]\(([^)]*)\)")
_HTML_IMG = re.compile(r"<img\b[^>]*>", re.I)


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def external_urls(text: str, allowed: frozenset[str]) -> list[str]:
    return [u for u in _URL_RE.findall(text) if _host(u) not in allowed]


def strip_untrusted_urls(text: str, allowed: frozenset[str]) -> tuple[str, int]:
    removed = 0

    def img(m: re.Match[str]) -> str:
        nonlocal removed
        if _host(m.group(1).strip()) in allowed:
            return m.group(0)
        removed += 1
        return "[image removed]"

    text = _MD_IMG.sub(img, text)
    for tag in _HTML_IMG.findall(text):
        removed += 1
        text = text.replace(tag, "[image removed]")

    def link(m: re.Match[str]) -> str:
        nonlocal removed
        if _host(m.group(0)) in allowed:
            return m.group(0)
        removed += 1
        return "[link removed]"

    return _URL_RE.sub(link, text), removed


class Engine:
    def __init__(self, settings: Settings, db: Database, provider, telemetry: Telemetry,
                 embedder: retrieval.HashingEmbedder | None = None, canary: str | None = None) -> None:
        self.settings = settings
        self.db = db
        self.provider = provider
        self.t = telemetry
        self.embedder = embedder or retrieval.HashingEmbedder()
        self.canary = canary or f"AEGIS-CANARY-{secrets.token_hex(4).upper()}"
        self._cache: OrderedDict[str, tuple[AskResult, str]] = OrderedDict()

    def has(self, control: str) -> bool:
        return self.settings.has(control)

    # ------------------------------------------------------------------ ingestion
    def ingest(self, user: User, title: str, content: str, request_id: str | None = None) -> str:
        rid = request_id or str(uuid.uuid4())
        g = guard.scan(f"{title}\n{content}")
        doc_id = self.db.add_document(user["tenant_id"], title, content, embedder=self.embedder, risk_score=g.score)
        self._cache.clear()  # cached answers may be stale after a corpus change
        self.t.emit("document_ingested", "info", request_id=rid, user=user, document_id=doc_id,
                    title_sha=digest(title), content_len=len(content))
        if g.blocked:  # detect-only at ingestion: legitimate security docs may contain these phrases
            self.t.emit("document_flagged", "medium", request_id=rid, user=user, document_id=doc_id,
                        score=g.score, categories=g.categories)
        return doc_id

    # ------------------------------------------------------------------ ask
    def ask(self, user: User, question: str, request_id: str | None = None) -> AskResult:
        rid = request_id or str(uuid.uuid4())
        tenant = user["tenant_id"]

        g = guard.scan(question)
        if g.blocked:
            ev = "input_guard_blocked" if self.has("input_guard") else "input_guard_would_block"
            self.t.emit(ev, "high" if self.has("input_guard") else "medium", request_id=rid, user=user,
                        score=g.score, categories=g.categories, input_sha=digest(question), input_len=len(question))
            if self.has("input_guard"):
                raise GuardBlocked(rid)

        key = self._cache_key(question, tenant)
        cached = self._cache.get(key)
        if cached is not None:
            result, origin = cached
            if origin != tenant:
                self.t.emit("cross_tenant_cache_hit", "critical", request_id=rid, user=user, origin_tenant=origin)
            self.t.emit("response_generated", "info", request_id=rid, user=user, cached=True)
            return AskResult(**{**result.__dict__, "request_id": rid, "cached": True})

        hits = retrieval.search(self.db, question, tenant, scoped=self.has("tenant_scope"), embedder=self.embedder)
        self._flag_foreign(hits, user, rid, via="retrieval")
        hits, quarantined = self._screen(hits, user, rid)

        blocks = [{"title": h.title, "text": h.text} for h in hits]
        hardened = self.has("prompt_hardening")
        nonce = prompts.new_nonce()
        system = prompts.build_system(self.canary, hardened)
        observations: list[str] = []
        trace: list[dict[str, Any]] = []
        limit = self.settings.max_tool_calls + 1 if self.has("tool_policy") else self.settings.uncontrolled_max_steps
        answer = ""
        for step in range(limit):
            req = ModelRequest(system, prompts.render_user(question, blocks, observations, hardened=hardened, nonce=nonce),
                               step=step, blocks=blocks, observations=list(observations))
            try:
                out = self.provider.generate(req)
            except ModelError as exc:
                self.t.emit("model_error", "medium", request_id=rid, user=user, error=str(exc)[:120])
                raise ModelUnavailable(rid) from exc
            call = tools.parse_tool_call(out)
            if call is None:
                answer = out
                break
            if step == limit - 1:
                self.t.emit("tool_loop_capped", "medium", request_id=rid, user=user, steps=step + 1)
                answer = "Stopped: tool-call limit reached."
                break
            entry, observation = self._run_tool(call, user, rid, len(trace))
            trace.append(entry)
            observations.append(observation[:OBS_MAX])

        result = self._finish(answer, hits, trace, quarantined, user, rid, system)
        if not trace:
            self._cache[key] = (result, tenant)
            while len(self._cache) > CACHE_MAX:
                self._cache.popitem(last=False)
        self.t.emit("response_generated", "info", request_id=rid, user=user, cached=False,
                    tool_calls=len(trace), quarantined=quarantined)
        return result

    def _cache_key(self, question: str, tenant: str) -> str:
        scope = f"|{tenant}" if self.has("cache_isolation") else ""
        return hashlib.sha256((textnorm.normalize(question) + scope).encode()).hexdigest()

    def _flag_foreign(self, hits, user: User, rid: str, via: str) -> None:
        foreign = [h for h in hits if h.tenant_id != user["tenant_id"]]
        if foreign:
            self.t.emit("cross_tenant_retrieval", "critical", request_id=rid, user=user, via=via,
                        foreign_count=len(foreign), foreign_tenants=sorted({h.tenant_id for h in foreign}))

    def _screen(self, hits, user: User, rid: str):
        """Retrieval guard. Poisoned chunks are QUARANTINED (dropped) and the answer continues
        from the clean ones, instead of failing the whole request."""
        kept, dropped = [], 0
        for h in hits:
            g = guard.scan(h.text)
            if g.blocked:
                enforced = self.has("retrieval_guard")
                self.t.emit("retrieval_chunk_quarantined" if enforced else "retrieval_chunk_flagged",
                            "high" if enforced else "medium", request_id=rid, user=user,
                            document_id=h.document_id, chunk_id=h.chunk_id, chunk_tenant=h.tenant_id,
                            score=g.score, categories=g.categories)
                if enforced:
                    dropped += 1
                    continue
            kept.append(h)
        return kept, dropped

    # ------------------------------------------------------------------ tools
    def _run_tool(self, call: tools.ToolCall, user: User, rid: str, made: int):
        spec = tools.TOOLS.get(call.name)
        self.t.emit("tool_call_requested", "info", request_id=rid, user=user, tool=call.name or "?", step=made)
        if self.has("tool_policy"):
            d = policy.authorize(self.settings, call, made)
            if d.verdict == "deny":
                self.t.emit("tool_call_denied", "high", request_id=rid, user=user, tool=call.name or "?",
                            reason=d.reason, **d.extra)
                return ({"tool": call.name, "status": "denied", "reason": d.reason},
                        f"Tool call denied: {d.reason}.")
            if d.verdict == "pending_approval":
                action_id = self.db.add_action(user["tenant_id"], user["user_id"], call.name, d.args, "pending_approval")
                self.t.emit("approval_requested", "medium", request_id=rid, user=user, tool=call.name, action_id=action_id)
                return ({"tool": call.name, "status": "pending_approval", "action_id": action_id},
                        "This action needs human approval and has not been performed.")
            return self._execute(spec, d.args, user, rid, approved=False)
        if spec is None or not isinstance(call.args, dict):
            self.t.emit("tool_call_failed", "low", request_id=rid, user=user, tool=call.name or "?")
            return ({"tool": call.name, "status": "error", "reason": "unknown_tool_or_args"}, "Tool error.")
        return self._execute(spec, call.args, user, rid, approved=False)

    def _execute(self, spec: tools.ToolSpec, args: dict[str, Any], user: User, rid: str, approved: bool):
        tenant, uid = user["tenant_id"], user["user_id"]
        if spec.name == "search_documents":
            target = str(args.get("tenant_id", tenant)) if "tenant_id" in args else tenant
            if target != tenant:  # only reachable when tool_policy is off: a confused-deputy hole
                self.t.emit("tenant_override_used", "critical", request_id=rid, user=user, requested_tenant=target)
            hits = retrieval.search(self.db, str(args.get("query", ""))[:200], target,
                                    scoped=self.has("tenant_scope"), top_k=int(args.get("top_k", 3) or 3),
                                    embedder=self.embedder)
            self._flag_foreign(hits, user, rid, via="tool")
            hits, _ = self._screen(hits, user, rid)
            text = "\n".join(f"[{h.title}] {h.text}" for h in hits) or "No results."
            self.t.emit("tool_call_executed", "info", request_id=rid, user=user, tool=spec.name,
                        state_changing=False, approved=approved)
            return {"tool": spec.name, "status": "executed", "results": len(hits)}, text
        if spec.name == "create_ticket":
            self.db.add_action(tenant, uid, spec.name, args, "executed")
            self.t.emit("tool_call_executed", "low" if approved else "medium", request_id=rid, user=user,
                        tool=spec.name, state_changing=True, approved=approved)
            return {"tool": spec.name, "status": "executed"}, "Ticket created."
        if spec.name == "send_webhook":
            url, body = str(args.get("url", "")), str(args.get("body", ""))
            host = tools.host_of(url) or "invalid"
            allowlisted = host in self.settings.egress_allowlist
            self.db.add_action(tenant, uid, spec.name, {"url": url, "body": body[:2000]}, "executed")
            self.t.emit("egress_executed", "low" if allowlisted else "critical", request_id=rid, user=user,
                        host=host, body_len=len(body), body_sha=digest(body), allowlisted=allowlisted)
            return {"tool": spec.name, "status": "executed", "host": host}, "Webhook recorded (simulated; nothing was sent)."
        return {"tool": spec.name, "status": "error"}, "Tool error."

    def approve(self, user: User, action_id: str) -> dict[str, Any]:
        action = self.db.get_action(action_id, user["tenant_id"])
        if action is None or action["status"] != "pending_approval":
            raise ActionNotFound(action_id)
        call = tools.ToolCall(action["tool"], action["args"])
        d = policy.authorize(self.settings, call, 0)
        if d.verdict == "deny":
            self.db.set_action_status(action_id, user["tenant_id"], "rejected")
            self.t.emit("tool_call_denied", "high", user=user, tool=action["tool"], reason=d.reason, at="approval")
            return {"id": action_id, "status": "rejected", "reason": d.reason}
        spec = tools.TOOLS[action["tool"]]
        self.db.set_action_status(action_id, user["tenant_id"], "executed")
        self.t.emit("approval_granted", "low", user=user, tool=action["tool"], action_id=action_id)
        self.t.emit("tool_call_executed", "low", user=user, tool=action["tool"], state_changing=spec.state_changing, approved=True)
        return {"id": action_id, "status": "executed"}

    def reject(self, user: User, action_id: str) -> dict[str, Any]:
        action = self.db.get_action(action_id, user["tenant_id"])
        if action is None or action["status"] != "pending_approval":
            raise ActionNotFound(action_id)
        self.db.set_action_status(action_id, user["tenant_id"], "rejected")
        self.t.emit("approval_rejected", "low", user=user, tool=action["tool"], action_id=action_id)
        return {"id": action_id, "status": "rejected"}

    # ------------------------------------------------------------------ output
    @staticmethod
    def _system_overlap(answer: str, system: str) -> list[str]:
        """System-prompt lines that appear verbatim in the answer (catches verbatim leaks only)."""
        return [ln for ln in system.splitlines() if len(ln.strip()) >= 30 and ln.strip() in answer]

    def _finish(self, answer: str, hits, trace, quarantined: int, user: User, rid: str, system: str = "") -> AskResult:
        raw = answer
        overlap = self._system_overlap(answer, system)
        if self.canary in answer or overlap:
            self.t.emit("canary_leak", "critical", request_id=rid, user=user,
                        kind="system_prompt" if not overlap else "system_prompt_verbatim", lines=len(overlap))
        if overlap and self.has("output_redaction"):
            for ln in overlap:
                answer = answer.replace(ln.strip(), "[REDACTED_SYSTEM_PROMPT]")
        allowed = self.settings.egress_allowlist
        ext = external_urls(answer, allowed)
        if ext:
            self.t.emit("external_url_in_output", "medium", request_id=rid, user=user, url_count=len(ext),
                        hosts=sorted({_host(u) for u in ext})[:5])
        if self.has("egress_filter"):
            answer, removed = strip_untrusted_urls(answer, allowed)
            if removed:
                self.t.emit("output_url_stripped", "high", request_id=rid, user=user, removed=removed)
        sources = list(dict.fromkeys(h.title for h in hits))
        counts: dict[str, int] = {}
        if self.has("output_redaction"):
            red = redact.redact(answer)
            answer, counts = red.text, red.counts
            sources = [redact.redact(s).text for s in sources]
            if counts:
                self.t.emit("pii_redacted", "low", request_id=rid, user=user, types=counts)
        else:
            exposed = redact.contains_sensitive(answer)
            if exposed:
                self.t.emit("pii_in_output", "medium", request_id=rid, user=user, types=exposed)
        return AskResult(answer, sources, sorted(self.settings.controls), trace, quarantined, counts, rid, raw_answer=raw)
