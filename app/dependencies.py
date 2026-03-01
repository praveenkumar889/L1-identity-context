"""
FastAPI Dependencies — Service Injection
=========================================

Provides singleton service instances to route handlers via Depends().
Initialised once at application startup via the lifespan context.
"""

from __future__ import annotations
from typing import Optional

from app.services.token_validation import TokenValidator
from app.services.user_enrichment import UserEnrichmentService
from app.services.role_resolver import RoleResolver
from app.services.signing import SecurityContextSigner
from app.services.redis_store import RedisStore
from app.services.rate_limiter import RateLimiter
from app.services.context_builder import ContextBuilder


class ServiceContainer:
    """Holds all service singletons.  Initialised in app lifespan."""

    def __init__(self):
        self.token_validator: Optional[TokenValidator] = None
        self.enrichment_service: Optional[UserEnrichmentService] = None
        self.role_resolver: Optional[RoleResolver] = None
        self.signer: Optional[SecurityContextSigner] = None
        self.redis_store: Optional[RedisStore] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.context_builder: Optional[ContextBuilder] = None

    def initialise(self) -> None:
        """Wire up all services."""
        self.token_validator = TokenValidator()
        self.enrichment_service = UserEnrichmentService()
        self.role_resolver = RoleResolver()
        self.signer = SecurityContextSigner()
        self.redis_store = RedisStore()
        self.rate_limiter = RateLimiter()
        self.context_builder = ContextBuilder(
            token_validator=self.token_validator,
            enrichment_service=self.enrichment_service,
            role_resolver=self.role_resolver,
            signer=self.signer,
            redis_store=self.redis_store,
        )


# Module-level singleton
container = ServiceContainer()


def get_context_builder() -> ContextBuilder:
    """FastAPI Depends() injection for ContextBuilder."""
    assert container.context_builder is not None, "Services not initialised"
    return container.context_builder


def get_redis_store() -> RedisStore:
    """FastAPI Depends() injection for RedisStore."""
    assert container.redis_store is not None, "Services not initialised"
    return container.redis_store


def get_signer() -> SecurityContextSigner:
    """FastAPI Depends() injection for SecurityContextSigner."""
    assert container.signer is not None, "Services not initialised"
    return container.signer


def get_token_validator() -> TokenValidator:
    """FastAPI Depends() injection for TokenValidator.
    Ensures BTG/Revoke routes share the same JWKS cache and mock keypair."""
    assert container.token_validator is not None, "Services not initialised"
    return container.token_validator


def get_rate_limiter() -> RateLimiter:
    """FastAPI Depends() injection for RateLimiter."""
    assert container.rate_limiter is not None, "Services not initialised"
    return container.rate_limiter
