"""Per-client request rate limiting (fixed one-minute windows)."""

from __future__ import annotations

import threading
import time
from typing import Protocol

from app.core.logging import get_logger

log = get_logger(__name__)


class RateLimiter(Protocol):
    def hit(self, key: str, limit: int) -> bool:
        """Record one request; return False if ``key`` is over ``limit`` this minute."""
        ...


class InMemoryRateLimiter:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, int], int] = {}
        self._lock = threading.Lock()

    def hit(self, key: str, limit: int) -> bool:
        window = int(time.time() // 60)
        with self._lock:
            # Drop old windows.
            for stale in [k for k in self._counts if k[1] < window]:
                del self._counts[stale]
            count = self._counts.get((key, window), 0) + 1
            self._counts[(key, window)] = count
        return count <= limit


class RedisRateLimiter:
    """Shared across API worker processes. Fails open if Redis is unavailable."""

    def __init__(self, redis_url: str) -> None:
        import redis

        self._client = redis.Redis.from_url(
            redis_url, socket_timeout=0.5, socket_connect_timeout=0.5
        )

    def hit(self, key: str, limit: int) -> bool:
        window = int(time.time() // 60)
        redis_key = f"ratelimit:{key}:{window}"
        try:
            pipe = self._client.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, 120)
            count, _ = pipe.execute()
        except Exception as exc:  # fail open: availability over strict limiting
            log.warning("rate_limiter_unavailable", error=type(exc).__name__)
            return True
        return int(count) <= limit
