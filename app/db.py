"""SQLite storage. Tenant scoping is FAIL-CLOSED: tenant-aware calls require a tenant id,
and the only way to read across tenants is a function whose name says it is unsafe."""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, text TEXT NOT NULL, embedding BLOB
);
CREATE INDEX IF NOT EXISTS idx_chunks_tenant ON chunks(tenant_id);
CREATE INDEX IF NOT EXISTS idx_docs_tenant ON documents(tenant_id);
CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, tool TEXT NOT NULL,
    args_json TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_actions_tenant ON actions(tenant_id);
"""


class QuotaExceeded(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_tenant(tenant_id: Any) -> str:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id is required and must be a non-empty string")
    return tenant_id


def split_text(text: str, size: int = 600, overlap: int = 100) -> list[str]:
    clean = " ".join(text.split())
    if not clean:
        return []
    chunks: list[str] = []
    start = 0
    while start < len(clean):
        end = min(start + size, len(clean))
        if end < len(clean):
            boundary = clean.rfind(". ", start + size // 2, end)
            if boundary != -1:
                end = boundary + 1
        piece = clean[start:end].strip()
        if piece:
            chunks.append(piece)
        if end >= len(clean):
            break
        start = max(end - overlap, start + 1)
    return chunks


class Database:
    def __init__(self, path: Path, *, max_docs_per_tenant: int = 500) -> None:
        self.path = Path(path)
        self.max_docs_per_tenant = max_docs_per_tenant

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:  # commit / rollback
                yield conn
        finally:
            conn.close()  # `with conn` does not close; do it explicitly

    def init(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._tx() as conn:
            conn.executescript(SCHEMA)

    def clear_all(self) -> None:
        with self._tx() as conn:
            conn.execute("DELETE FROM chunks")
            conn.execute("DELETE FROM documents")
            conn.execute("DELETE FROM actions")

    # ------------------------------------------------------------ documents
    def add_document(self, tenant_id: str, title: str, content: str, *, embedder=None, risk_score: float = 0.0) -> str:
        _require_tenant(tenant_id)
        doc_id = str(uuid.uuid4())
        pieces = split_text(content)
        with self._tx() as conn:
            count = conn.execute("SELECT COUNT(*) FROM documents WHERE tenant_id=?", (tenant_id,)).fetchone()[0]
            if count >= self.max_docs_per_tenant:
                raise QuotaExceeded(f"Document quota of {self.max_docs_per_tenant} reached for tenant")
            conn.execute(
                "INSERT INTO documents (id, tenant_id, title, content, risk_score, created_at) VALUES (?,?,?,?,?,?)",
                (doc_id, tenant_id, title, content, risk_score, _now()),
            )
            for i, piece in enumerate(pieces):
                emb = embedder.pack(embedder.embed(piece)) if embedder else None
                conn.execute(
                    "INSERT INTO chunks (id, document_id, tenant_id, chunk_index, text, embedding) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), doc_id, tenant_id, i, piece, emb),
                )
        return doc_id

    def list_documents(self, tenant_id: str) -> list[dict[str, Any]]:
        _require_tenant(tenant_id)
        with self._tx() as conn:
            rows = conn.execute(
                "SELECT id, title, created_at FROM documents WHERE tenant_id=? ORDER BY created_at DESC", (tenant_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    _CHUNK_SQL = (
        "SELECT c.id AS chunk_id, c.document_id, c.tenant_id, c.text, c.embedding, d.title "
        "FROM chunks c JOIN documents d ON d.id = c.document_id"
    )

    def iter_chunks(self, tenant_id: str) -> list[dict[str, Any]]:
        """Chunks for ONE tenant. Raises if no tenant is given (fail-closed)."""
        _require_tenant(tenant_id)
        with self._tx() as conn:
            rows = conn.execute(self._CHUNK_SQL + " WHERE c.tenant_id=?", (tenant_id,)).fetchall()
        return [dict(r) for r in rows]

    def iter_chunks_all_tenants_unsafe(self) -> list[dict[str, Any]]:
        """Cross-tenant read. Exists only so the uncontrolled lab configurations can be demonstrated."""
        with self._tx() as conn:
            rows = conn.execute(self._CHUNK_SQL).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------ actions (tools / approvals)
    def add_action(self, tenant_id: str, user_id: str, tool: str, args: dict[str, Any], status: str) -> str:
        _require_tenant(tenant_id)
        action_id = str(uuid.uuid4())
        with self._tx() as conn:
            conn.execute(
                "INSERT INTO actions (id, tenant_id, user_id, tool, args_json, status, created_at) VALUES (?,?,?,?,?,?,?)",
                (action_id, tenant_id, user_id, tool, json.dumps(args, ensure_ascii=False), status, _now()),
            )
        return action_id

    def get_action(self, action_id: str, tenant_id: str) -> dict[str, Any] | None:
        _require_tenant(tenant_id)
        with self._tx() as conn:
            row = conn.execute("SELECT * FROM actions WHERE id=? AND tenant_id=?", (action_id, tenant_id)).fetchone()
        return self._action(row)

    def set_action_status(self, action_id: str, tenant_id: str, status: str) -> None:
        _require_tenant(tenant_id)
        with self._tx() as conn:
            conn.execute("UPDATE actions SET status=? WHERE id=? AND tenant_id=?", (status, action_id, tenant_id))

    def list_actions(self, tenant_id: str, status: str | None = None) -> list[dict[str, Any]]:
        _require_tenant(tenant_id)
        sql, params = "SELECT * FROM actions WHERE tenant_id=?", [tenant_id]
        if status:
            sql += " AND status=?"
            params.append(status)
        with self._tx() as conn:
            rows = conn.execute(sql + " ORDER BY created_at", params).fetchall()
        return [self._action(r) for r in rows]  # type: ignore[misc]

    def all_actions_unsafe(self) -> list[dict[str, Any]]:
        with self._tx() as conn:
            rows = conn.execute("SELECT * FROM actions ORDER BY created_at").fetchall()
        return [self._action(r) for r in rows]  # type: ignore[misc]

    @staticmethod
    def _action(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        out = dict(row)
        out["args"] = json.loads(out.pop("args_json"))
        return out
