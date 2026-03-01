"""
signing.py — HMAC-SHA256 SecurityContext Signing
=================================================

Signs the SecurityContext deterministically so downstream layers can verify
that the context was not tampered with in transit.

Flow:
  1. Serialise SecurityContext to canonical JSON (sorted keys, no whitespace)
  2. Compute HMAC-SHA256 over the canonical bytes
  3. Return hex digest as signature

Verification (by any downstream layer):
  1. Re-serialise the received SecurityContext identically
  2. Recompute HMAC-SHA256
  3. Compare (constant-time) with received signature
"""

from __future__ import annotations
import hmac
import hashlib
import json
import logging
from datetime import datetime

from app.config import get_settings
from app.models.security_context import SecurityContext

logger = logging.getLogger("l1.signing")


class SecurityContextSigner:
    """
    Signs and verifies SecurityContext objects using HMAC-SHA256.

    The signing key is L1_HMAC_SECRET_KEY (env-driven, must be rotated in prod).
    """

    def __init__(self):
        self._settings = get_settings()

    # ── Canonical serialisation ──

    @staticmethod
    def _canonical_json(ctx: SecurityContext) -> bytes:
        """Serialise SecurityContext to deterministic canonical JSON.

        Rules:
          - Keys sorted alphabetically at every nesting level
          - No whitespace (separators = (',', ':'))
          - datetime → ISO 8601 string
          - Enums → their .value
          - UTF-8 encoded bytes

        This ensures that the same SecurityContext always produces
        the same byte string, regardless of Python dict ordering.
        """
        def _default(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            if hasattr(obj, "value"):  # enums
                return obj.value
            raise TypeError(f"Cannot serialise {type(obj)}")

        raw = ctx.model_dump()
        canonical = json.dumps(
            raw,
            sort_keys=True,
            separators=(",", ":"),
            default=_default,
            ensure_ascii=True,
        )
        return canonical.encode("utf-8")

    # ── Sign ──

    def sign(self, ctx: SecurityContext) -> str:
        """
        Compute HMAC-SHA256 signature of the SecurityContext.

        Returns:
            Hex-encoded HMAC-SHA256 digest (64 chars).
        """
        payload = self._canonical_json(ctx)
        sig = hmac.new(
            key=self._settings.HMAC_SECRET_KEY.encode("utf-8"),
            msg=payload,
            digestmod=hashlib.sha256,
        ).hexdigest()

        logger.debug(
            "SecurityContext signed | ctx_id=%s sig_prefix=%s... payload_bytes=%d",
            ctx.ctx_id, sig[:16], len(payload),
        )
        return sig

    # ── Verify ──

    def verify(self, ctx: SecurityContext, signature: str) -> bool:
        """
        Verify that a signature matches the SecurityContext.

        Uses hmac.compare_digest for constant-time comparison
        to prevent timing attacks.
        """
        expected = self.sign(ctx)
        valid = hmac.compare_digest(expected, signature)

        if not valid:
            logger.warning(
                "Signature verification FAILED | ctx_id=%s", ctx.ctx_id,
            )
        return valid
