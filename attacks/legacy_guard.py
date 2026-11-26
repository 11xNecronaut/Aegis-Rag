"""The v0.1 guard from the original ChatGPT-built MVP, kept verbatim as a measurable baseline."""
import re

INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"disregard (all )?(previous|prior|above) instructions",
    r"reveal (the )?(system prompt|hidden prompt|secret|confidential)",
    r"exfiltrat(e|ion)",
    r"send (the )?(data|secret|credentials|document) (to|outside)",
    r"bypass (the )?(security|access|permission) (controls|checks)",
    r"you are now (an? )?(unrestricted|different) assistant",
]


def detect_prompt_injection(text: str) -> list[str]:
    lowered = text.lower()
    return [p for p in INJECTION_PATTERNS if re.search(p, lowered)]
