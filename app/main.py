"""
L1 Identity & Context -- FastAPI Application
=============================================

Apollo Hospitals Zero Trust NL-to-SQL Pipeline
Layer 1: Identity & Context Resolution (v2.0)

This service:
  1. Validates Azure AD JWTs (RS256 + JWKS)
  2. Enriches identity with org context (mock HR/LDAP)
  3. Resolves role inheritance (mock Neo4j DAG)
  4. Computes clearance + MFA-based sensitivity cap
  5. Builds and signs SecurityContext (HMAC-SHA256)
  6. Stores in Redis with TTL (900s normal / 14400s BTG)
  7. Exposes ctx_token + signature for downstream layers
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.dependencies import container
from app.api.routes import router, mock_router


def _configure_logging():
    settings = get_settings()
    level = logging.DEBUG if settings.DEBUG else logging.INFO
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)-24s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()
    root.addHandler(handler)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    logger = logging.getLogger("l1.main")
    settings = get_settings()

    # ── Validate critical configuration ──
    settings.validate_for_startup()

    logger.info("=" * 60)
    logger.info("L1 Identity & Context -- Starting v%s", settings.SERVICE_VERSION)
    logger.info("  Mock IdP: %s  |  Redis: %s", settings.MOCK_IDP_ENABLED, settings.REDIS_URL)
    logger.info("  TTL Normal: %ds  |  BTG: %ds", settings.CONTEXT_TTL_NORMAL, settings.CONTEXT_TTL_EMERGENCY)
    logger.info("=" * 60)
    container.initialise()
    logger.info("All services initialised")
    yield
    logger.info("L1 Identity & Context -- Shutting down")


app = FastAPI(
    title="L1 Identity & Context",
    description=(
        "Apollo Hospitals Zero Trust NL-to-SQL Pipeline -- Layer 1.\n\n"
        "Validates Azure AD JWTs (RS256/JWKS), enriches identity, resolves role "
        "inheritance, computes clearance with MFA sensitivity cap, builds "
        "HMAC-SHA256-signed SecurityContext, stores in Redis with TTL.\n\n"
        "**Primary output:** `ctx_token` + `signature` consumed by L2-L8."
    ),
    version="2.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(router)

# ── Mock IdP routes: ONLY registered when MOCK_IDP_ENABLED=true ──
# This prevents the /mock/token endpoint from existing in production builds.
if get_settings().MOCK_IDP_ENABLED:
    app.include_router(mock_router)
