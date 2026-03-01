"""
redis_store.py — Session Storage & Token Revocation
====================================================

Responsibilities:
  1. Store SecurityContext with TTL (keyed by ctx_id)
  2. Retrieve SecurityContext by ctx_id
  3. Delete / revoke SecurityContext
  4. JTI blacklist — track revoked JWT IDs to prevent replay
  5. Auto-expire entries via Redis TTL

Fallback:
  If Redis is unavailable, uses an in-memory dict with manual TTL checks.
  This keeps the service running in dev/test without Redis infrastructure.
"""

from __future__ import annotations
import json
import time
import logging
from typing import Optional
from datetime import datetime

from app.config import get_settings
from app.models.security_context import SecurityContext

logger = logging.getLogger("l1.redis_store")


class RedisStore:
    """
    Redis-backed session store with in-memory fallback.

    Keys:
      zt:l1:ctx:{ctx_id}           → serialised SecurityContext (TTL = context TTL)
      zt:l1:jti:blacklist:{jti}    → "1" (TTL = token max lifetime)
    """

    def __init__(self):
        self._settings = get_settings()
        self._redis = None
        self._memory_store: dict[str, tuple[str, float]] = {}  # key → (value, expire_at)
        self._init_redis()

    def _init_redis(self):
        """Try to connect to Redis.  Fall back silently to in-memory."""
        try:
            import redis as redis_lib
            self._redis = redis_lib.Redis.from_url(
                self._settings.REDIS_URL,
                decode_responses=True,
                socket_connect_timeout=2,
            )
            self._redis.ping()
            logger.info("Redis connected: %s", self._settings.REDIS_URL)
        except Exception as e:
            logger.warning("Redis unavailable (%s) — using in-memory fallback", e)
            self._redis = None

    # ─────────────────────────────────────────────────────
    # LOW-LEVEL OPS (Redis or in-memory)
    # ─────────────────────────────────────────────────────

    def _set(self, key: str, value: str, ttl_seconds: int) -> None:
        if self._redis:
            self._redis.setex(key, ttl_seconds, value)
        else:
            self._memory_store[key] = (value, time.time() + ttl_seconds)

    def _get(self, key: str) -> Optional[str]:
        if self._redis:
            return self._redis.get(key)
        else:
            entry = self._memory_store.get(key)
            if entry is None:
                return None
            value, expire_at = entry
            if time.time() > expire_at:
                del self._memory_store[key]
                return None
            return value

    def _delete(self, key: str) -> bool:
        if self._redis:
            return bool(self._redis.delete(key))
        else:
            return self._memory_store.pop(key, None) is not None

    def _exists(self, key: str) -> bool:
        if self._redis:
            return bool(self._redis.exists(key))
        else:
            entry = self._memory_store.get(key)
            if entry is None:
                return False
            _, expire_at = entry
            if time.time() > expire_at:
                del self._memory_store[key]
                return False
            return True

    # ─────────────────────────────────────────────────────
    # SECURITY CONTEXT STORAGE
    # ─────────────────────────────────────────────────────

    def _ctx_key(self, ctx_id: str) -> str:
        return f"{self._settings.REDIS_KEY_PREFIX}ctx:{ctx_id}"

    def store_context(self, ctx: SecurityContext) -> None:
        """Store a SecurityContext with its TTL."""
        key = self._ctx_key(ctx.ctx_id)

        # Custom serialiser for datetime/enum
        def _default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):
                return obj.value
            raise TypeError(f"Not serialisable: {type(obj)}")

        value = json.dumps(ctx.model_dump(), default=_default, sort_keys=True)
        self._set(key, value, ctx.ttl_seconds)
        logger.info("Context stored | ctx_id=%s ttl=%ds", ctx.ctx_id, ctx.ttl_seconds)

    def get_context(self, ctx_id: str, signature: str = None, signer=None) -> Optional[SecurityContext]:
        """Retrieve a SecurityContext by ctx_id.  Returns None if expired/missing.

        If both signature and signer are provided, re-verifies the HMAC before
        returning.  This protects against Redis tampering.
        """
        key = self._ctx_key(ctx_id)
        raw = self._get(key)
        if raw is None:
            logger.debug("Context not found: %s", ctx_id)
            return None

        try:
            data = json.loads(raw)
            ctx = SecurityContext(**data)
        except Exception as e:
            logger.error("Failed to deserialise context %s: %s", ctx_id, e)
            return None

        # ── Optional HMAC re-verification (defence against Redis tampering) ──
        if signature and signer:
            if not signer.verify(ctx, signature):
                logger.warning(
                    "INTEGRITY VIOLATION — stored context signature mismatch | ctx_id=%s",
                    ctx_id,
                )
                return None

        return ctx

    def delete_context(self, ctx_id: str) -> bool:
        """Delete a SecurityContext (revocation)."""
        key = self._ctx_key(ctx_id)
        deleted = self._delete(key)
        logger.info("Context deleted | ctx_id=%s deleted=%s", ctx_id, deleted)
        return deleted

    def update_context(self, ctx: SecurityContext) -> None:
        """Overwrite an existing SecurityContext (e.g., after BTG activation)."""
        self.store_context(ctx)  # setex overwrites

    # ─────────────────────────────────────────────────────
    # JTI BLACKLIST (token revocation)
    # ─────────────────────────────────────────────────────

    def _jti_key(self, jti: str) -> str:
        return f"{self._settings.REDIS_JTI_BLACKLIST_PREFIX}{jti}"

    def blacklist_jti(self, jti: str, ttl_seconds: int = 86400) -> None:
        """Add a JWT ID to the blacklist.  TTL should match token max lifetime."""
        key = self._jti_key(jti)
        self._set(key, "1", ttl_seconds)
        logger.info("JTI blacklisted | jti=%s ttl=%ds", jti, ttl_seconds)

    def is_jti_blacklisted(self, jti: str) -> bool:
        """Check if a JWT ID has been revoked."""
        key = self._jti_key(jti)
        blacklisted = self._exists(key)
        if blacklisted:
            logger.warning("Blacklisted JTI detected: %s", jti)
        return blacklisted
