"""Bounded in-process sliding-window rate limiter for single-process deployments."""

from collections import deque
from threading import Lock
from time import monotonic
from collections.abc import Callable


class RateLimiter:
    def __init__(self, limit: int = 120, window_seconds: float = 60.0,
                 *, clock: Callable[[], float] = monotonic, max_keys: int = 4096):
        if limit < 1 or window_seconds <= 0 or max_keys < 1:
            raise ValueError("Rate limit settings must be positive")
        self.limit, self.window_seconds = limit, window_seconds
        self.max_keys, self._clock = max_keys, clock
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            events = self._events.get(key)
            if events is None:
                self._prune(cutoff)
                if len(self._events) >= self.max_keys:
                    return False
                events = self._events[key] = deque()
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= self.limit:
                return False
            events.append(now)
            return True

    def _prune(self, cutoff: float) -> None:
        for key in [k for k, v in self._events.items() if not v or v[-1] <= cutoff]:
            self._events.pop(key, None)
