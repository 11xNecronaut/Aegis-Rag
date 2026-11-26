"""Structured security telemetry with hard size limits.

Events never contain raw prompts, document bodies, tool payloads or secrets: only
lengths, digests, categories and identifiers. Every string is clipped, the file is
size-capped with rotation, so a hostile client cannot grow the log without bound.
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

SCHEMA_VERSION = 2
MAX_STR = 200
MAX_LIST = 20


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]


def _clean(value: Any, depth: int = 0) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= MAX_STR else value[:MAX_STR] + "…"
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_clean(v, depth + 1) for v in list(value)[:MAX_LIST]]
    if isinstance(value, dict) and depth < 2:
        return {str(k)[:MAX_STR]: _clean(v, depth + 1) for k, v in list(value.items())[:MAX_LIST]}
    return str(type(value).__name__)


class Telemetry:
    def __init__(
        self,
        path: Path | None = None,
        *,
        max_bytes: int = 5_000_000,
        backups: int = 3,
        sink: Callable[[dict[str, Any]], None] | None = None,
        mode: str = "",
    ) -> None:
        self.path = Path(path) if path else None
        self.max_bytes = max_bytes
        self.backups = backups
        self.sink = sink
        self.mode = mode
        self._lock = threading.Lock()

    def emit(
        self,
        event_type: str,
        severity: str,
        *,
        request_id: str | None = None,
        user: dict[str, str] | None = None,
        **details: Any,
    ) -> dict[str, Any]:
        event = {
            "schema": SCHEMA_VERSION,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
            "request_id": request_id or "-",
            "event_type": event_type,
            "severity": severity,
            "user_id": (user or {}).get("user_id", "anonymous"),
            "tenant_id": (user or {}).get("tenant_id", "unknown"),
            "mode": self.mode,
            "details": _clean(details),
        }
        if self.sink is not None:
            self.sink(event)
        if self.path is not None:
            self._write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
        return event

    def _write(self, line: str) -> None:
        assert self.path is not None
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size + len(line) > self.max_bytes:
                self._rotate()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)

    def _rotate(self) -> None:
        assert self.path is not None
        oldest = self.path.with_name(f"{self.path.name}.{self.backups}")
        oldest.unlink(missing_ok=True)
        for i in range(self.backups - 1, 0, -1):
            src = self.path.with_name(f"{self.path.name}.{i}")
            if src.exists():
                src.rename(self.path.with_name(f"{self.path.name}.{i + 1}"))
        self.path.rename(self.path.with_name(f"{self.path.name}.1"))
