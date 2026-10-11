"""In-memory hourly limits. One Render free instance keeps a single counter.

Counters live in this process only. A restart or spin-down clears them. The free plan
has no database, so they are not shared across deploys.
"""

import ipaddress
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


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def client_ip(request: Request) -> str:
    """Prefer Cloudflare's client address, then the socket peer.

    X-Forwarded-For is ignored. On Render the last hop is the platform proxy, and a
    client can append its own value. CF-Connecting-IP is used only when it parses as
    an IP, which is the case when Cloudflare is the edge that set the header.
    Without Cloudflare, request.client.host is that proxy, so the per-IP cap is coarse
    and the per-session cap is the quota that matters.
    """
    cloudflare = _valid_ip(request.headers.get("cf-connecting-ip", ""))
    if cloudflare:
        return cloudflare
    if request.client and request.client.host:
        peer = _valid_ip(request.client.host)
        if peer:
            return peer
    return "unknown"
