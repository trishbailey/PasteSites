"""In-memory hourly limits. One Render free instance keeps a single counter."""

import threading
import time

from starlette.requests import Request


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = {}

    def allow(self, key: str, limit: int, window: int = 3600) -> bool:
        now = time.time()
        with self._lock:
            recent = [stamp for stamp in self._events.get(key, []) if now - stamp < window]
            if len(recent) >= limit:
                self._events[key] = recent
                return False
            recent.append(now)
            self._events[key] = recent
            return True

    def remaining(self, key: str, limit: int, window: int = 3600) -> int:
        now = time.time()
        with self._lock:
            recent = [stamp for stamp in self._events.get(key, []) if now - stamp < window]
            self._events[key] = recent
            return max(0, limit - len(recent))

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if parts:
            return parts[-1][:80]
    if request.client and request.client.host:
        return request.client.host
    return "unknown"
