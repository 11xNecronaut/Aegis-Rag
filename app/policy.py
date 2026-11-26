"""Deterministic tool policy. Everything here depends only on trusted configuration and
the caller's identity, never on what the model says or what a document claims."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app import tools
from app.config import Settings


@dataclass
class Decision:
    verdict: str  # allow | deny | pending_approval
    reason: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


def authorize(settings: Settings, call: tools.ToolCall, calls_made: int) -> Decision:
    if call.malformed:
        return Decision("deny", "malformed_tool_call")
    spec = tools.TOOLS.get(call.name)
    if spec is None or call.name not in settings.tool_allowlist:
        return Decision("deny", "tool_not_allowlisted")
    if calls_made >= settings.max_tool_calls:
        return Decision("deny", "tool_call_cap")
    v = tools.validate_strict(spec, call.args)
    if not v.ok:
        extra = {"unknown_args": v.unknown, "tenant_override_attempt": "tenant_id" in v.unknown}
        return Decision("deny", v.reason, extra=extra)
    if spec.egress:
        host = tools.host_of(str(v.args.get("url", "")))
        url = str(v.args.get("url", ""))
        if host is None or not url.lower().startswith("https://") or host not in settings.egress_allowlist:
            return Decision("deny", "egress_host_not_allowed", extra={"host": host or "invalid"})
    if spec.state_changing:
        return Decision("pending_approval", "human_approval_required", v.args)
    return Decision("allow", "", v.args)
