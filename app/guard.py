"""Heuristic prompt-injection detector (v2).

This is a PROBABILISTIC control. It is deliberately explainable and cheap, and it WILL
be evaded by a motivated attacker (synonyms, paraphrase, languages not listed). The
attack runner measures how often, so the claim is a number rather than a hope.

Improvements over v0.1: input is normalised first (invisible characters, homoglyphs,
spacing, base64), rules carry weights and categories instead of being one flat list,
scores combine with noisy-OR so two weak signals can add up, and multilingual
"ignore previous instructions" variants are covered.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from app import textnorm

BLOCK_THRESHOLD = 0.6
MAX_SCAN_CHARS = 8000


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(unicodedata.normalize("NFKC", pattern))


# (category, rule_id, weight, pattern). Patterns run on normalised (lowercase, collapsed) text.
RULES: list[tuple[str, str, float, re.Pattern[str]]] = [
    ("override", "override_verb_target", 0.7, _p(
        r"\b(?:ignore|disregard|forget|override|bypass|skip|discard|abandon|overlook|set aside)\b.{0,40}?"
        r"\b(?:previous|prior|above|earlier|preceding|original|existing|all|any|your|these|those|the)\b.{0,30}?"
        r"\b(?:instructions?|rules?|directives?|guidelines?|prompts?|polic(?:y|ies)|restrictions?|constraints?|safeguards?|programming|training)\b")),
    ("override", "from_now_on", 0.5, _p(
        r"\bfrom now on\b.{0,60}?\b(?:you|your|assistant)\b.{0,40}?\b(?:must|will|are|only|never|always|should|shall)\b")),
    ("override", "new_instructions_header", 0.5, _p(r"\bnew (?:instructions?|rules?|system prompt|directives?)\b\s*[:\-]")),
    ("roleplay", "you_are_now", 0.4, _p(r"\byou are now\b")),
    ("roleplay", "unrestricted_persona", 0.7, _p(
        r"\b(?:pretend|act|behave|roleplay|role-play|imagine)\b.{0,30}?\b(?:as|like|to be|you are)\b.{0,50}?"
        r"\b(?:unrestricted|unfiltered|jailbroken|evil|dan|developer mode|no (?:rules|restrictions|limits|filters))\b")),
    ("roleplay", "jailbreak_terms", 0.5, _p(
        r"\b(?:developer mode|jailbreak(?:ed)?|do anything now|dan mode|no (?:rules|restrictions|limitations|filters))\b")),
    ("extraction", "reveal_system_prompt", 0.7, _p(
        r"\b(?:reveal|print|show|display|repeat|output|leak|dump|tell me|give me|expose|disclose|recite|echo|quote|reproduce|transcribe)\b.{0,30}?"
        r"\b(?:system|hidden|initial|developer|your)\b.{0,15}?\b(?:prompt|instructions?|configuration|config|reference id)\b")),
    ("extraction", "what_is_your_prompt", 0.5, _p(r"\b(?:what|which)\b.{0,15}?\b(?:your|the)\b.{0,15}?\b(?:system prompt|initial instructions)\b")),
    ("extraction", "repeat_above", 0.4, _p(r"\brepeat (?:the |everything |all )?.{0,30}?\b(?:above|before this|so far|verbatim)\b")),
    ("exfil", "send_to_url", 0.7, _p(
        r"\b(?:send|post|upload|forward|transmit|deliver|submit|email|exfiltrate|leak|share|embed|encode)\b.{0,80}?(?:https?://|www\.)")),
    ("exfil", "markdown_image_url", 0.6, _p(r"!\[[^\]]{0,80}\]\(\s*https?://")),
    ("exfil", "html_image_url", 0.6, _p(r"<img[^>]{0,200}src\s*=\s*[\"']?https?://")),
    ("exfil", "exfiltrate_word", 0.2, _p(r"\bexfiltrat\w*")),
    ("tool", "tool_call_forge", 0.7, _p(r"\btool_call\s*:")),
    ("tool", "json_tool_forge", 0.5, _p(r"\"tool\"\s*:\s*\"")),
    ("tool", "invoke_tool", 0.5, _p(r"\b(?:call|invoke|use|run|execute|trigger)\b.{0,25}?\b(?:tool|function|send_webhook|create_ticket|search_documents)\b")),
    ("tool", "tool_names", 0.3, _p(r"\b(?:send_webhook|create_ticket|search_documents)\b")),
    ("structure", "fake_role_header", 0.4, _p(r"\b(?:system|assistant|developer|administrator)\s*(?:message|override|note|instruction)?\s*:")),
    ("structure", "chat_template_tokens", 0.7, _p(r"<\|?(?:im_start|im_end|system|endoftext|eot_id)\|?>|\[/?inst\]|<<sys>>")),
    ("structure", "fake_end_of_context", 0.6, _p(r"end of (?:the )?(?:document|context|untrusted)|\[end document\]|<<\s*end")),
    ("tenant", "tenant_param", 0.5, _p(r"\btenant[_ -]?id\s*[:=]|\btenant_id\b")),
    ("tenant", "other_tenant", 0.4, _p(r"\b(?:all|other|another|different) tenants?\b")),
    ("tenant", "tenant_identifier", 0.3, _p(r"\btenant-[a-z0-9_-]+\b")),
    # Multilingual "ignore previous instructions" (each is a strong signal on its own).
    ("override", "override_es", 0.7, _p(r"\b(?:ignora|ignorar|olvida|olvidar)\b.{0,20}?\binstrucciones\b.{0,15}?\b(?:anteriores|previas)\b")),
    ("override", "override_fr", 0.7, _p(r"\bignore[zr]?\b.{0,20}?\binstructions\b.{0,15}?\b(?:pr[eé]c[eé]dentes|ant[eé]rieures)\b")),
    ("override", "override_de", 0.7, _p(r"\bignorier(?:e|en)?\b.{0,20}?\b(?:vorherigen|bisherigen|obigen|vorigen)\b.{0,10}?\banweisungen\b")),
    ("override", "override_pt", 0.7, _p(r"\bignor(?:e|ar)\b.{0,20}?\binstru[cç][oõ]es\b.{0,15}?\banteriores\b")),
    ("override", "override_it", 0.7, _p(r"\bignora\b.{0,20}?\bistruzioni\b.{0,15}?\bprecedenti\b")),
    ("override", "override_ru", 0.7, _p(r"игнорируй(?:те)?.{0,20}?(?:предыдущие|прежние).{0,10}?инструкции")),
    ("override", "override_zh", 0.7, _p(r"(?:忽略|无视|忘记)(?:之前|以上|先前|上述)?的?(?:所有)?(?:指令|指示|说明)")),
    ("override", "override_hi", 0.7, _p(r"निर्देशों?\s*को\s*(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)")),
    ("extraction", "extraction_multilingual", 0.7, _p(
        r"\b(?:muestra|muéstrame|afficher?|affiche|zeige)\b.{0,30}?(?:prompt del sistema|prompt syst[eè]me|system-?prompt)")),
]


@dataclass(frozen=True)
class Finding:
    category: str
    rule: str
    weight: float
    view: str  # "plain" or "decoded"


@dataclass(frozen=True)
class GuardResult:
    score: float
    findings: tuple[Finding, ...]
    threshold: float = BLOCK_THRESHOLD

    @property
    def blocked(self) -> bool:
        return self.score >= self.threshold

    @property
    def categories(self) -> list[str]:
        return sorted({f.category for f in self.findings})

    @property
    def rules(self) -> list[str]:
        return sorted({f.rule for f in self.findings})


def _combine(weights: list[float]) -> float:
    remaining = 1.0
    for w in weights:
        remaining *= 1.0 - w
    return round(1.0 - remaining, 4)


def scan(text: str, threshold: float = BLOCK_THRESHOLD) -> GuardResult:
    text = text[:MAX_SCAN_CHARS]
    views = textnorm.views(text)
    findings: dict[str, Finding] = {}
    decoded_hit = False
    for index, view in enumerate(views):
        is_decoded = index > 0 and view not in views[:3] and textnorm.has_decoded_view(text)
        for category, rule, weight, pattern in RULES:
            if pattern.search(view) and rule not in findings:
                findings[rule] = Finding(category, rule, weight, "decoded" if is_decoded else "plain")
                decoded_hit = decoded_hit or is_decoded
    if decoded_hit:
        findings["encoded_payload"] = Finding("obfuscation", "encoded_payload", 0.5, "decoded")
    return GuardResult(_combine([f.weight for f in findings.values()]), tuple(findings.values()), threshold)
