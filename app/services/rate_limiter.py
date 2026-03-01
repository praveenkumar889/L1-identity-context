"""
rate_limiter.py — In-Memory Rate Limiter
==========================================

Lightweight token-bucket rate limiter using only stdlib.
No external dependencies (slowapi/redis-based limiters can replace this in production).

Usage:
    limiter = RateLimiter()

    # In route:
    limiter.check("resolve", client_ip, max_requests=30, window_seconds=60)
"""

from __future__ import annotations
import time
import logging
from collections import defaultdict
from threading import Lock
from fastapi import HTTPException

logger = logging.getLogger("l1.rate_limiter")


class RateLimiter:
    """
    Simple sliding-window rate limiter backed by in-memory dict.

    Thread-safe via Lock.  Entries auto-expire on access.

    Production replacement: Redis-backed sliding window or slowapi.
    """

    def __init__(self):
        # key → list of request timestamps
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def _cleanup(self, key: str, window_seconds: int) -> None:
        """Remove timestamps older than the window."""
        cutoff = time.time() - window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def check(
        self,
        endpoint: str,
        client_ip: str,
        max_requests: int = 30,
        window_seconds: int = 60,
    ) -> None:
        """
        Check rate limit.  Raises HTTP 429 if exceeded.

        Args:
            endpoint:       Endpoint name (e.g., "resolve", "btg")
            client_ip:      Client IP for per-IP limiting
            max_requests:   Max requests per window
            window_seconds: Window size in seconds
        """
        key = f"{endpoint}:{client_ip}"
        now = time.time()

        with self._lock:
            self._cleanup(key, window_seconds)

            if len(self._requests[key]) >= max_requests:
                logger.warning(
                    "RATE LIMIT EXCEEDED | endpoint=%s ip=%s count=%d limit=%d/%ds",
                    endpoint, client_ip, len(self._requests[key]),
                    max_requests, window_seconds,
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {max_requests} requests per {window_seconds}s. Try again later.",
                    headers={"Retry-After": str(window_seconds)},
                )

            self._requests[key].append(now)
