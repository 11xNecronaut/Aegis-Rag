"""Sensitive-data detection and redaction with validators.

Detectors that can be checked mathematically are (Luhn for cards, Verhoeff for Aadhaar),
which removes most false positives. This is still not a certified DLP product: it finds
well-formed identifiers and well-known secret shapes, not free-text secrets.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

# ---------------------------------------------------------------- checksum helpers
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_valid(number: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][int(ch)]]
    return str(_VERHOEFF_INV[c])


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


def _entropy(s: str) -> float:
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


# ---------------------------------------------------------------- detectors
_DIGITS = re.compile(r"\D")
_CANARY = re.compile(r"AEGIS-CANARY-[A-Z0-9]{6,}")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_GITHUB = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_AWS_ID = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b")
_KV_SECRET = re.compile(r"(?i)\b(api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|password|passwd|pwd)\b(\s*[:=]\s*)(['\"]?)([^\s'\"]{8,})")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_AADHAAR = re.compile(r"(?<![\d-])([2-9]\d{3})[ -]?(\d{4})[ -]?(\d{4})(?![\d-])")
_PAN = re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b")
_PHONE_IN = re.compile(r"(?<![\w+-])(?:\+?91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}(?![\w-])")
_PHONE_INTL = re.compile(r"(?<![\w+])\+\d{1,3}[ -]?\(?\d{1,4}\)?[ -]?\d{3,4}[ -]?\d{3,4}(?!\d)")
_PHONE_US = re.compile(r"(?<![\w-])\(?\b\d{3}\)?[ .-]\d{3}[ .-]\d{4}(?![\w-])")
_HIGH_ENTROPY_40 = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])")


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


def _sub(text: str, pattern: re.Pattern[str], label: str, counts: dict[str, int], validator=None) -> str:
    def repl(m: re.Match[str]) -> str:
        if validator is not None and not validator(m):
            return m.group(0)
        counts[label] = counts.get(label, 0) + 1
        return f"[REDACTED_{label.upper()}]"
    return pattern.sub(repl, text)


def _secret_like(m: re.Match[str]) -> bool:
    s = m.group(0)
    return (any(c.isupper() for c in s) and any(c.islower() for c in s) and any(c.isdigit() or c in "/+" for c in s)
            and _entropy(s) >= 4.0)


def redact(text: str) -> RedactionResult:
    counts: dict[str, int] = {}
    t = text
    t = _sub(t, _CANARY, "canary", counts)
    t = _sub(t, _PRIVATE_KEY, "private_key", counts)
    t = _sub(t, _JWT, "jwt", counts)
    t = _sub(t, _GITHUB, "token", counts)
    t = _sub(t, _SLACK, "token", counts)
    t = _sub(t, _GOOGLE_KEY, "api_key", counts)
    t = _sub(t, _AWS_ID, "cloud_key", counts)

    def kv(m: re.Match[str]) -> str:
        counts["secret"] = counts.get("secret", 0) + 1
        return f"{m.group(1)}{m.group(2)}{m.group(3)}[REDACTED_SECRET]"
    t = _KV_SECRET.sub(kv, t)

    t = _sub(t, _HIGH_ENTROPY_40, "secret", counts, _secret_like)
    t = _sub(t, _EMAIL, "email", counts)
    t = _sub(t, _CARD, "card", counts, lambda m: 13 <= len(_DIGITS.sub("", m.group(0))) <= 19 and luhn_valid(_DIGITS.sub("", m.group(0))))
    t = _sub(t, _AADHAAR, "aadhaar", counts, lambda m: verhoeff_valid("".join(m.groups())))
    t = _sub(t, _PAN, "pan", counts)
    t = _sub(t, _PHONE_IN, "phone", counts)
    t = _sub(t, _PHONE_INTL, "phone", counts)
    t = _sub(t, _PHONE_US, "phone", counts)
    return RedactionResult(t, counts)


def contains_sensitive(text: str) -> dict[str, int]:
    """Counts of sensitive items present (without returning or logging the values)."""
    return redact(text).counts
