"""
token_validation.py — JWT Validation Service
=============================================

Validates Azure AD JWTs using RS256 + JWKS endpoint.

Verification chain:
  1. Fetch JWKS from Azure AD (cached)
  2. Match kid in JWT header to JWKS key
  3. Verify signature (RS256)
  4. Verify standard claims: iss, aud, exp, nbf, iat
  5. Extract identity claims: oid/sub, name, email, roles, groups, amr, jti
  6. Return typed claims dict for downstream enrichment

In mock mode (MOCK_IDP_ENABLED=True):
  Uses locally generated RSA keypair instead of Azure AD JWKS.
"""

from __future__ import annotations
import time
import logging
from typing import Optional, Any
from dataclasses import dataclass, field

import jwt as pyjwt
from jwt import PyJWKClient, PyJWKClientError
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

from app.config import get_settings

logger = logging.getLogger("l1.token_validation")


# ─────────────────────────────────────────────────────────
# EXTRACTED CLAIMS (typed output of validation)
# ─────────────────────────────────────────────────────────

@dataclass
class ValidatedClaims:
    """Typed claims extracted from a validated JWT."""
    oid: str                                # Azure AD Object ID (oid or sub)
    name: str                               # Display name
    email: str                              # preferred_username or email
    roles: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    amr: list[str] = field(default_factory=list)  # Authentication methods
    jti: str = ""                           # JWT ID (unique token identifier)
    raw_claims: dict = field(default_factory=dict)


# ─────────────────────────────────────────────────────────
# MOCK RSA KEYPAIR (dev/test only)
# ─────────────────────────────────────────────────────────

class MockKeyPair:
    """Generates and holds an RSA keypair for local JWT signing/verification.
    Used when MOCK_IDP_ENABLED=True (no Azure AD dependency)."""

    _instance: Optional["MockKeyPair"] = None

    def __init__(self):
        logger.info("[MockIdP] Generating RSA-%d keypair for local JWT signing",
                     get_settings().MOCK_IDP_RSA_KEY_SIZE)
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=get_settings().MOCK_IDP_RSA_KEY_SIZE,
            backend=default_backend(),
        )
        self._public_key = self._private_key.public_key()

    @classmethod
    def get(cls) -> "MockKeyPair":
        if cls._instance is None:
            cls._instance = MockKeyPair()
        return cls._instance

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key

    @property
    def public_key_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_jwt(self, payload: dict, kid: str = "mock-key-1") -> str:
        """Sign a JWT payload with the mock private key."""
        return pyjwt.encode(
            payload,
            self._private_key,
            algorithm="RS256",
            headers={"kid": kid},
        )


# ─────────────────────────────────────────────────────────
# TOKEN VALIDATOR
# ─────────────────────────────────────────────────────────

class TokenValidator:
    """
    Validates JWTs against Azure AD JWKS (or mock keypair in dev).

    Usage:
        validator = TokenValidator()
        claims = validator.validate("eyJ...")
        # claims.oid, claims.name, claims.roles, etc.
    """

    def __init__(self):
        self._settings = get_settings()
        self._jwks_client: Optional[PyJWKClient] = None
        self._jwks_last_fetch: float = 0

    # ── JWKS Client (lazy init, cached) ──

    def _get_jwks_client(self) -> Optional[PyJWKClient]:
        """Get or create the JWKS client.  Returns None in mock mode."""
        if self._settings.MOCK_IDP_ENABLED:
            return None

        now = time.time()
        if (
            self._jwks_client is None
            or (now - self._jwks_last_fetch) > self._settings.JWKS_CACHE_TTL_SECONDS
        ):
            logger.info("Fetching JWKS from %s", self._settings.JWKS_URI)
            self._jwks_client = PyJWKClient(self._settings.JWKS_URI)
            self._jwks_last_fetch = now

        return self._jwks_client

    # ── Signing Key Resolution ──

    def _resolve_signing_key(self, token: str) -> Any:
        """Resolve the public key to verify the JWT signature.

        In mock mode → uses the MockKeyPair public key.
        In production → fetches from Azure AD JWKS endpoint, matched by kid.
        """
        if self._settings.MOCK_IDP_ENABLED:
            return MockKeyPair.get().public_key

        client = self._get_jwks_client()
        if client is None:
            raise TokenValidationError("JWKS client not available")

        try:
            signing_key = client.get_signing_key_from_jwt(token)
            return signing_key.key
        except PyJWKClientError as e:
            logger.error("JWKS key resolution failed: %s", e)
            raise TokenValidationError(f"Cannot resolve signing key: {e}")

    # ── Core Validation ──

    def validate(self, token: str) -> ValidatedClaims:
        """
        Validate a JWT and extract claims.

        Verification steps:
          1. Resolve signing key (JWKS or mock)
          2. Verify RS256 signature
          3. Verify iss, aud, exp, nbf, iat
          4. Extract identity claims

        Raises:
            TokenValidationError on any failure.
        """
        try:
            key = self._resolve_signing_key(token)
        except Exception as e:
            raise TokenValidationError(f"Key resolution failed: {e}")

        try:
            decoded = pyjwt.decode(
                token,
                key,
                algorithms=[self._settings.JWT_ALGORITHM],
                audience=self._settings.AZURE_CLIENT_ID,
                issuer=self._settings.AZURE_ISSUER,
                leeway=self._settings.JWT_LEEWAY_SECONDS,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require": ["exp", "nbf", "iat", "iss", "aud"],
                },
            )
        except pyjwt.ExpiredSignatureError:
            raise TokenValidationError("Token has expired")
        except pyjwt.InvalidAudienceError:
            raise TokenValidationError("Invalid audience")
        except pyjwt.InvalidIssuerError:
            raise TokenValidationError("Invalid issuer")
        except pyjwt.InvalidSignatureError:
            raise TokenValidationError("Invalid signature")
        except pyjwt.DecodeError as e:
            raise TokenValidationError(f"Token decode failed: {e}")
        except pyjwt.InvalidTokenError as e:
            raise TokenValidationError(f"Token validation failed: {e}")

        # ── Extract Claims ──
        oid = decoded.get("oid") or decoded.get("sub", "")
        name = decoded.get("name", "")
        email = decoded.get("preferred_username") or decoded.get("email", "")
        roles = decoded.get("roles", [])
        groups = decoded.get("groups", [])
        amr = decoded.get("amr", [])
        jti_val = decoded.get("jti", "")

        if not oid:
            raise TokenValidationError("Token missing required claim: oid or sub")
        if not jti_val:
            raise TokenValidationError("Token missing required claim: jti (required for revocation support)")

        logger.info(
            "Token validated | oid=%s name=%s roles=%s mfa=%s",
            oid, name, roles, "mfa" in amr,
        )

        return ValidatedClaims(
            oid=oid,
            name=name,
            email=email,
            roles=roles if isinstance(roles, list) else [roles],
            groups=groups if isinstance(groups, list) else [groups],
            amr=amr if isinstance(amr, list) else [amr],
            jti=jti_val,
            raw_claims=decoded,
        )


# ─────────────────────────────────────────────────────────
# EXCEPTION
# ─────────────────────────────────────────────────────────

class TokenValidationError(Exception):
    """Raised when JWT validation fails at any step."""
    pass
