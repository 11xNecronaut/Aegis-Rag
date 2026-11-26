"""Text normalisation so pattern matching sees what a language model would read.

Attackers hide instructions with zero-width characters, homoglyphs, odd spacing and
encodings. A regex that runs on raw text never sees them; a model often does.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

_CONFUSABLES = str.maketrans(
    {
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
        "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ѡ": "w",
        "α": "a", "ε": "e", "ι": "i", "ο": "o", "ρ": "p", "ν": "v", "κ": "k", "υ": "u",
    }
)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_SPACED_RE = re.compile(r"\b(?:\w ){3,}\w\b")
_SEP_RE = re.compile(r"(?<=\w)[\-_.*·]+(?=\w)")
MAX_VIEWS = 6


def normalize(text: str) -> str:
    """NFKC, lowercase, drop invisible/format characters, fold lookalikes, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text).lower()
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.translate(_CONFUSABLES)
    return re.sub(r"\s+", " ", text).strip()


def _b64_decodes(text: str) -> list[str]:
    out: list[str] = []
    for match in _B64_RE.findall(text):
        padded = match + "=" * (-len(match) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch in "\n\t" for ch in decoded)
        if len(decoded) >= 8 and printable / len(decoded) >= 0.9:
            out.append(decoded)
    return out


def views(text: str) -> list[str]:
    """Return distinct normalised readings of the text (plain, de-spaced, de-separated, decoded)."""
    text = text[:20000]
    primary = normalize(text)
    candidates = [primary]
    despaced = _SPACED_RE.sub(lambda m: m.group().replace(" ", ""), primary)
    candidates.append(despaced)
    candidates.append(_SEP_RE.sub("", primary))
    for decoded in _b64_decodes(text):
        candidates.append(normalize(decoded))
    seen: list[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.append(c)
    return seen[:MAX_VIEWS]


def has_decoded_view(text: str) -> bool:
    return bool(_b64_decodes(text[:20000]))
