"""
API Request & Response Models
=============================

Typed contracts for the two endpoints:
  POST /resolve-security-context
  POST /break-glass
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime

from app.models.enums import ClearanceLevel, Domain, EmergencyMode


# ─────────────────────────────────────────────────────────
# POST /resolve-security-context
# ─────────────────────────────────────────────────────────

class ContextPreview(BaseModel):
    """Lightweight summary included in the response so callers don't
    need to deserialise the full SecurityContext for basic routing."""
    oid: str
    name: str
    email: str
    department: str
    domain: Domain
    direct_roles: list[str]
    effective_roles: list[str]
    clearance_level: int
    sensitivity_cap: int
    mfa_verified: bool
    emergency_mode: EmergencyMode


class ResolveContextResponse(BaseModel):
    """Response from POST /resolve-security-context."""
    ctx_token: str = Field(..., description="Opaque context ID (ctx_<uuid>) — use as key for downstream calls")
    signature: str = Field(..., description="HMAC-SHA256 hex digest of the SecurityContext")
    expires_in: int = Field(..., description="TTL in seconds")
    created_at: datetime
    context_preview: ContextPreview


# ─────────────────────────────────────────────────────────
# POST /break-glass
# ─────────────────────────────────────────────────────────

class BreakGlassRequest(BaseModel):
    """Request body for BTG activation."""
    ctx_token: str = Field(..., description="Existing ctx_token from /resolve-security-context")
    reason: str = Field(..., min_length=20, description="Clinical justification (min 20 chars)")
    patient_id: Optional[str] = Field(None, description="Patient ID if applicable")


class BreakGlassResponse(BaseModel):
    """Response from POST /break-glass."""
    ctx_token: str
    signature: str
    expires_in: int
    emergency_mode: EmergencyMode
    previous_clearance: int
    elevated_clearance: int
    message: str


# ─────────────────────────────────────────────────────────
# POST /revoke
# ─────────────────────────────────────────────────────────

class RevokeRequest(BaseModel):
    ctx_token: str


class RevokeResponse(BaseModel):
    revoked: bool
    ctx_token: str
    message: str


# ─────────────────────────────────────────────────────────
# ERRORS
# ─────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str
    detail: str
    status_code: int
