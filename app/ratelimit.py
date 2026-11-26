"""Small in-memory token bucket. Single-process only; use a shared store when scaled out."""
from __future__ import annotations

import threading
import time
from typing import Callable


class RateLimiter:
    def __init__(self, per_minute: int, burst: int | None = None, clock: Callable[[], float] = time.monotonic, max_keys: int = 10_000):
        self.rate = per_minute / 60.0
        self.capacity = float(burst if burst is not None else per_minute)
        self.clock = clock
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _refill(self, key: str) -> float:
        now = self.clock()
        tokens, last = self._buckets.get(key, (self.capacity, now))
        return min(self.capacity, tokens + (now - last) * self.rate)

    def allow(self, key: str) -> bool:
        with self._lock:
            if len(self._buckets) >= self.max_keys and key not in self._buckets:
                self._buckets.clear()  # bound memory under key-flooding
            tokens = self._refill(key)
            ok = tokens >= 1.0
            self._buckets[key] = (tokens - 1.0 if ok else tokens, self.clock())
            return ok

    def peek(self, key: str) -> bool:
        with self._lock:
            return self._refill(key) >= 1.0
