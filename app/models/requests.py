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
from app.models.security_context import SecurityContext


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
    """Response from POST /resolve-security-context.
    
    Returns a lightweight summary for the client.
    Full SecurityContext is stored in Redis for downstream layers.
    """
    context_token_id: str = Field(..., description="Opaque context ID (ctx_<uuid>)")
    user_id: str = Field(..., description="User OID")
    effective_roles: list[str] = Field(..., description="Resolved effective roles")
    max_clearance_level: int = Field(..., description="User's clearance level")
    context_type: str = Field(default="NORMAL", description="Context type (NORMAL or EMERGENCY)")
    ttl_seconds: int = Field(..., description="TTL in seconds")
    signature: str = Field(..., description="HMAC-SHA256 hex digest")


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
