"""
L1 Identity & Context — Configuration
======================================

All tunables are environment-variable-driven (prefix: L1_).
Secrets MUST be overridden in production via env or vault.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    """Centralised configuration for the Identity & Context layer."""

    # ── Service ──
    SERVICE_NAME: str = "l1-identity-context"
    SERVICE_VERSION: str = "2.0.0"
    DEBUG: bool = False

    # ── Azure AD / OIDC ──
    AZURE_TENANT_ID: str = "apollo-mock-tenant"
    AZURE_CLIENT_ID: str = "apollo-zt-pipeline"                       # expected 'aud'
    AZURE_ISSUER: str = "https://login.microsoftonline.com/apollo-mock-tenant/v2.0"
    JWKS_URI: str = (
        "https://login.microsoftonline.com/apollo-mock-tenant/discovery/v2.0/keys"
    )
    JWKS_CACHE_TTL_SECONDS: int = 3600                                # re-fetch keys every hour

    # ── JWT Validation ──
    JWT_ALGORITHM: str = "RS256"
    JWT_LEEWAY_SECONDS: int = 30                                      # clock skew tolerance

    # ── Static keypair (optional) ──
    # If provided, these PEM files are used for signing/verification regardless
    # of MOCK_IDP_ENABLED.  This allows the service to operate with a fixed
    # keypair in any environment.
    JWT_PRIVATE_KEY_PATH: str | None = None
    JWT_PUBLIC_KEY_PATH: str | None = None

    # ── SecurityContext ──
    CONTEXT_TTL_NORMAL: int = 900                                     # 15 minutes
    CONTEXT_TTL_EMERGENCY: int = 14400                                # 4 hours (BTG)

    # ── HMAC Signing ──
    HMAC_SECRET_KEY: str = ""                                         # MUST be set via L1_HMAC_SECRET_KEY env
    HMAC_SECRET_KEY_MIN_LENGTH: int = 32                              # minimum key length

    # ── Redis ──
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_KEY_PREFIX: str = "zt:l1:"
    REDIS_JTI_BLACKLIST_PREFIX: str = "zt:l1:jti:blacklist:"

    # ── Break-the-Glass ──
    BTG_MIN_REASON_LENGTH: int = 20
    BTG_MAX_DURATION_SECONDS: int = 14400                             # 4 hours

    # ── Mock IdP (dev only — generates RSA keypair + test JWTs) ──
    MOCK_IDP_ENABLED: bool = True
    # MOCK_IDP_ENABLED: bool = False
    MOCK_IDP_RSA_KEY_SIZE: int = 2048

    # ── Data paths ──
    DATA_DIR: str = "app/data"

    # ── CORS ──
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",         # dev frontend
        "http://localhost:8001",         # Swagger UI
        "https://*.apollohospitals.com", # production
    ]

    def validate_for_startup(self) -> None:
        """Validate critical configuration at startup.
        Raises ValueError if production-critical settings are missing."""
        if not self.HMAC_SECRET_KEY:
            if self.MOCK_IDP_ENABLED:
                # Auto-generate a dev key when mock mode is on
                import secrets
                object.__setattr__(self, 'HMAC_SECRET_KEY',
                    f"dev-auto-{secrets.token_hex(32)}")
            else:
                raise ValueError(
                    "L1_HMAC_SECRET_KEY must be set in production. "
                    "Set this environment variable to a strong random secret "
                    f"(minimum {self.HMAC_SECRET_KEY_MIN_LENGTH} characters)."
                )
        if len(self.HMAC_SECRET_KEY) < self.HMAC_SECRET_KEY_MIN_LENGTH:
            raise ValueError(
                f"L1_HMAC_SECRET_KEY must be at least {self.HMAC_SECRET_KEY_MIN_LENGTH} characters. "
                f"Current length: {len(self.HMAC_SECRET_KEY)}"
            )

    class Config:
        env_prefix = "L1_"
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
