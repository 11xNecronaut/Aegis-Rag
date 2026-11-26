"""Small statistics helpers. Wilson intervals behave well at 0% and 100%, unlike the normal approximation."""
from __future__ import annotations

import math


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def fmt_rate(successes: int, n: int) -> str:
    lo, hi = wilson(successes, n)
    return f"{pct(successes / n if n else 0)} [{pct(lo)}-{pct(hi)}] (n={n})"
