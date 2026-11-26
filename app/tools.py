"""Tool registry, strict argument validation and tool-call parsing.

The model PROPOSES tool calls; it never executes them. Validation is strict
(unknown keys rejected, types and lengths enforced) because the most common agent
flaw is accepting a model-supplied argument that should have come from identity, such
as a tenant id."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Param:
    kind: str  # "str" | "int"
    required: bool = True
    max_len: int = 0
    lo: int = 0
    hi: int = 0


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    params: dict[str, Param]
    state_changing: bool = False
    egress: bool = False


TOOLS: dict[str, ToolSpec] = {
    "search_documents": ToolSpec(
        "search_documents", "Search the caller's own documents.",
        {"query": Param("str", True, 200), "top_k": Param("int", False, lo=1, hi=5)}),
    "create_ticket": ToolSpec(
        "create_ticket", "Create a helpdesk ticket (state-changing).",
        {"title": Param("str", True, 120), "body": Param("str", False, 1000)}, state_changing=True),
    "send_webhook": ToolSpec(
        "send_webhook", "POST data to an external URL (simulated, egress).",
        {"url": Param("str", True, 300), "body": Param("str", False, 2000)}, egress=True),
}


def describe_tools() -> str:
    out = []
    for spec in TOOLS.values():
        args = ", ".join(f"{k}:{p.kind}{'' if p.required else '?'}" for k, p in spec.params.items())
        out.append(f"- {spec.name}({args}): {spec.description}")
    return "\n".join(out)


@dataclass
class Validation:
    ok: bool
    reason: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    unknown: list[str] = field(default_factory=list)


def validate_strict(spec: ToolSpec, args: Any) -> Validation:
    if not isinstance(args, dict):
        return Validation(False, "args_not_object")
    unknown = sorted(set(args) - set(spec.params))
    if unknown:
        return Validation(False, "unexpected_args", unknown=unknown)
    clean: dict[str, Any] = {}
    for name, p in spec.params.items():
        if name not in args:
            if p.required:
                return Validation(False, f"missing_arg:{name}")
            continue
        value = args[name]
        if p.kind == "str":
            if not isinstance(value, str):
                return Validation(False, f"bad_type:{name}")
            if p.max_len and len(value) > p.max_len:
                return Validation(False, f"too_long:{name}")
        elif p.kind == "int":
            if isinstance(value, bool) or not isinstance(value, int) or not (p.lo <= value <= p.hi):
                return Validation(False, f"bad_value:{name}")
        clean[name] = value
    return Validation(True, args=clean)


@dataclass
class ToolCall:
    name: str
    args: Any
    malformed: bool = False


MAX_CALL_CHARS = 4000


def parse_tool_call(text: str) -> ToolCall | None:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.upper().startswith("TOOL_CALL:"):
            payload = stripped.split(":", 1)[1].strip()
            if len(payload) > MAX_CALL_CHARS:
                return ToolCall("", {}, malformed=True)
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                return ToolCall("", {}, malformed=True)
            if not isinstance(data, dict) or not isinstance(data.get("tool"), str):
                return ToolCall("", {}, malformed=True)
            return ToolCall(data["tool"], data.get("args", {}))
    return None


def host_of(url: str) -> str | None:
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    return parts.hostname.lower()
