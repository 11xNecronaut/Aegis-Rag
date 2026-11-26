"""Model providers.

extractive : echoes retrieved text (no model; cannot be injected)
sim        : SimulatedModel, a TEST DOUBLE that obeys instructions found in its input
             with probability `obedience`. It is NOT evidence about any real LLM. It exists
             to test whether deterministic controls hold when the model is compromised.
ollama     : local model via the Ollama HTTP API (not exercised in this repo's CI)
bedrock    : Amazon Bedrock Converse API (not exercised in this repo's CI)
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

import httpx

from app import textnorm

NO_ANSWER = "I couldn't find anything relevant in the documents you can access."


class ModelError(Exception):
    pass


@dataclass
class ModelRequest:
    system: str
    user: str
    step: int = 0
    blocks: list[dict] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)


def extractive_answer(blocks: list[dict]) -> str:
    if not blocks:
        return NO_ANSWER
    snippets = "\n\n".join(f"Source: {b['title']}\n{b['text']}" for b in blocks)
    return f"Relevant information found in your accessible documents:\n\n{snippets}"


class ExtractiveProvider:
    name = "extractive"

    def generate(self, req: ModelRequest) -> str:
        return extractive_answer(req.blocks)


# --------------------------------------------------------------------------- simulated model
_URL = r"(https?://[^\s)\]>\"']+)"
_EXFIL = re.compile(
    r"\b(?:send|post|forward|transmit|deliver|upload|submit|email|relay|dispatch|copy|hand over|pass along|share|leak|exfiltrate)\b"
    r"[^.!?\n]{0,100}?" + _URL)
_IMAGE = re.compile(r"!\[([^\]]*)\]\((https?://[^)\s]+)\)")
_TENANT = re.compile(
    r"search_documents[^\n]{0,120}?\bquery\W{1,4}([a-z0-9 _-]{1,60}?)\W{1,3}(?:and|,)\s+tenant_id\W{0,4}(tenant-[a-z0-9_-]+)")
_TICKET = re.compile(r"create (?:a |an )?ticket[^.!?\n]{0,30}?(?:titled|called|named)\s+[\"“”']([^\"“”']{1,100})[\"“”']")
_SYSPROMPT = [
    re.compile(r"\b(?:reveal|print|show|display|repeat|output|disclose|recite|quote|leak|echo|reproduce|transcribe)\b[^.!?\n]{0,50}?"
               r"(?:system prompt|hidden prompt|initial instructions|your instructions|reference id|internal reference)"),
    re.compile(r"(?:instructions|prompt)\s+you\s+(?:were|have been)\s+given"),
    re.compile(r"what were you told (?:before|at the start)"),
    re.compile(r"\bmuestra\b[^.!?\n]{0,30}?prompt del sistema"),
    re.compile(r"\baffiche\b[^.!?\n]{0,30}?prompt syst[eè]me"),
    re.compile(r"\bzeige\b[^.!?\n]{0,30}?system-?prompt"),
]
_SECRET = re.compile(r"\b[A-Z][A-Z0-9]{2,}(?:-[A-Z0-9]{2,}){1,3}\b")
_REVERSE = re.compile(r"\b(?:backwards|in reverse|reversed|reverse order)\b")
_KIND_ORDER = {"tenant_search": 0, "exfil": 1, "ticket": 2, "sysprompt": 3, "image": 4, "reverse": 5}


@dataclass(frozen=True)
class Directive:
    kind: str
    key: str
    data: tuple


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:)!?'\"")


def find_directives(text: str) -> list[Directive]:
    """Everything the simulated model recognises as an instruction, reading ALL normalised
    views of the text (so it 'understands' homoglyphs, zero-width tricks and base64)."""
    found: dict[tuple[str, str], Directive] = {}

    def add(kind: str, key: str, data: tuple) -> None:
        # URL-bearing directives are de-duplicated on their alphanumeric form so a view that
        # stripped separators (and mangled the URL) cannot create a second, bogus directive.
        ident = re.sub(r"[^a-z0-9]", "", key) if kind in ("exfil", "image") else key
        found.setdefault((kind, ident), Directive(kind, key, data))

    for view in textnorm.views(text):
        for m in _TENANT.finditer(view):
            add("tenant_search", f"{m.group(2)}|{m.group(1).strip()}", (m.group(1).strip(), m.group(2)))
        for m in _EXFIL.finditer(view):
            url = _clean_url(m.group(1))
            add("exfil", url, (url,))
        for m in _TICKET.finditer(view):
            add("ticket", m.group(1), (m.group(1).strip(),))
        if any(p.search(view) for p in _SYSPROMPT):
            add("sysprompt", "sys", ())
        if _REVERSE.search(view):
            add("reverse", "rev", ())
        for m in _IMAGE.finditer(view):
            add("image", _clean_url(m.group(2)), (m.group(1), _clean_url(m.group(2))))
    return sorted(found.values(), key=lambda d: (_KIND_ORDER[d.kind], d.key))


class SimProvider:
    name = "sim"

    def __init__(self, obedience: float = 1.0, seed: int = 0, trial: int = 0) -> None:
        self.obedience = obedience
        self.seed = seed
        self.trial = trial

    def _obeys(self, req: ModelRequest, d: Directive) -> bool:
        if self.obedience >= 1.0:
            return True
        if self.obedience <= 0.0:
            return False
        h = hashlib.sha256(f"{self.seed}|{self.trial}|{req.step}|{d.kind}|{d.key}".encode()).digest()
        return int.from_bytes(h[:8], "big") / 2**64 < self.obedience

    def generate(self, req: ModelRequest) -> str:
        directives = [d for d in find_directives(req.user) if self._obeys(req, d)]
        secrets_seen = list(dict.fromkeys(_SECRET.findall(req.user)))
        calls = [d for d in directives if d.kind in ("tenant_search", "exfil", "ticket")]
        if req.step < len(calls):
            d = calls[req.step]
            if d.kind == "tenant_search":
                call = {"tool": "search_documents", "args": {"query": d.data[0], "tenant_id": d.data[1]}}
            elif d.kind == "exfil":
                body = "; ".join(secrets_seen)[:1500] or "no-secrets-found"
                call = {"tool": "send_webhook", "args": {"url": d.data[0], "body": body}}
            else:
                call = {"tool": "create_ticket", "args": {"title": d.data[0], "body": "Requested by document."}}
            return "TOOL_CALL: " + json.dumps(call)
        parts: list[str] = []
        if any(d.kind == "sysprompt" for d in directives):
            reverse = any(d.kind == "reverse" for d in directives)
            parts.append("My system prompt is:\n" + (req.system[::-1] if reverse else req.system))
        parts.append(extractive_answer(req.blocks))
        if req.observations:
            parts.append("Tool results:\n" + "\n".join(req.observations))
        for d in directives:
            if d.kind == "image":
                parts.append(f"![{d.data[0]}]({d.data[1]}{'+'.join(secrets_seen)})")
        return "\n\n".join(parts)


# --------------------------------------------------------------------------- real providers
_THINK = re.compile(r"<think>.*?</think>", re.S)


class OllamaProvider:
    name = "ollama"

    def __init__(self, url: str, model: str, timeout: float = 120.0) -> None:
        self.url, self.model, self.timeout = url, model, timeout

    def generate(self, req: ModelRequest) -> str:
        payload = {
            "model": self.model, "stream": False, "options": {"temperature": 0},
            "messages": [{"role": "system", "content": req.system}, {"role": "user", "content": req.user}],
        }
        try:
            resp = httpx.post(f"{self.url}/api/chat", json=payload, timeout=self.timeout)
            resp.raise_for_status()
            content = resp.json()["message"]["content"]
        except (httpx.HTTPError, KeyError, ValueError) as exc:
            raise ModelError(f"ollama request failed: {type(exc).__name__}") from exc
        return _THINK.sub("", content).strip()


class BedrockProvider:
    name = "bedrock"

    def __init__(self, model_id: str, region: str) -> None:
        if not model_id:
            raise ModelError("AEGIS_BEDROCK_MODEL_ID is required for the bedrock provider")
        try:
            import boto3  # optional dependency
        except ImportError as exc:
            raise ModelError("boto3 is not installed (pip install boto3)") from exc
        self.model_id = model_id
        self.client = boto3.client("bedrock-runtime", region_name=region)

    def generate(self, req: ModelRequest) -> str:
        try:
            resp = self.client.converse(
                modelId=self.model_id,
                system=[{"text": req.system}],
                messages=[{"role": "user", "content": [{"text": req.user}]}],
                inferenceConfig={"maxTokens": 1024, "temperature": 0.0},
            )
            return "".join(part.get("text", "") for part in resp["output"]["message"]["content"]).strip()
        except Exception as exc:  # botocore raises many types; never leak details to callers
            raise ModelError(f"bedrock request failed: {type(exc).__name__}") from exc


def get_provider(settings: Any, *, seed: int = 0, trial: int = 0):
    kind = settings.llm_provider
    if kind == "extractive":
        return ExtractiveProvider()
    if kind == "sim":
        return SimProvider(settings.sim_obedience, seed, trial)
    if kind == "ollama":
        return OllamaProvider(settings.ollama_url, settings.ollama_model)
    if kind == "bedrock":
        return BedrockProvider(settings.bedrock_model_id, settings.bedrock_region)
    raise ValueError(f"unknown provider {kind}")
