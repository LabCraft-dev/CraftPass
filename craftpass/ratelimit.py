"""In-memory sliding-window rate limiter.

Single-process by design (uvicorn runs one worker), locked because FastAPI
serves sync routes from a threadpool. Uses ``time.monotonic`` so wall-clock
adjustments cannot extend or shorten a window.
"""

from __future__ import annotations

import threading
import time
from collections import deque

_MAX_TRACKED_KEYS = 10_000


class SlidingWindowLimiter:
    def __init__(self, max_events: int, window_seconds: float) -> None:
        if max_events < 1:
            raise ValueError("max_events must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._max = max_events
        self._window = float(window_seconds)
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def blocked(self, key: str, now: float | None = None) -> bool:
        """True when `key` has already hit the limit inside the window."""
        now = time.monotonic() if now is None else now
        with self._lock:
            dq = self._events.get(key)
            if dq is None:
                return False
            self._trim(dq, now)
            if not dq:
                del self._events[key]
                return False
            return len(dq) >= self._max

    def record(self, key: str, now: float | None = None) -> None:
        """Record one event (a failed attempt) for `key`."""
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._events) >= _MAX_TRACKED_KEYS and key not in self._events:
                self._evict_oldest()
            dq = self._events.setdefault(key, deque())
            self._trim(dq, now)
            dq.append(now)

    # -- internals ----------------------------------------------------------
    def _trim(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def _evict_oldest(self) -> None:
        victim = min(
            self._events,
            key=lambda k: self._events[k][-1] if self._events[k] else float("inf"),
            default=None,
        )
        if victim is not None:
            del self._events[victim]
