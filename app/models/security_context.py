"""
SecurityContext — Primary Output of L1
======================================

This is THE structured object that travels through every layer of the
Zero Trust pipeline.  L2 (Knowledge Graph), L4 (Policy Resolution),
L6 (Validation), L7 (Execution), and L8 (Audit) all consume this.

Layout mirrors the spec:
  ├── identity          — who is this user
  ├── org_context       — where do they sit in the organisation
  ├── authorization     — what can they access (roles, clearance, policies)
  ├── request_metadata  — how/when/where did the request originate
  └── emergency         — break-the-glass state
"""

from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from datetime import datetime

from app.models.enums import ClearanceLevel, Domain, EmergencyMode, EmploymentStatus


# ─────────────────────────────────────────────────────────
# IDENTITY BLOCK
# ─────────────────────────────────────────────────────────

class IdentityBlock(BaseModel):
    """JWT-verified identity claims."""
    model_config = ConfigDict(frozen=True)

    oid: str = Field(..., description="Azure AD Object ID (oid) or sub claim")
    name: str = Field(..., description="Display name from JWT")
    email: str = Field(..., description="preferred_username or email claim")
    jti: str = Field(..., description="JWT ID — unique token identifier")
    mfa_verified: bool = Field(False, description="True if 'mfa' present in amr claim")
    auth_methods: list[str] = Field(default_factory=list, description="amr claim values")


# ─────────────────────────────────────────────────────────
# ORG CONTEXT BLOCK (from enrichment — mock LDAP/HR)
# ─────────────────────────────────────────────────────────

class OrgContextBlock(BaseModel):
    """Organisational context — enriched from HR/LDAP systems."""
    model_config = ConfigDict(frozen=True)
    employee_id: str
    department: str
    facility_ids: list[str] = Field(default_factory=list)
    unit_ids: list[str] = Field(default_factory=list)
    provider_npi: Optional[str] = Field(None, description="National Provider Identifier (clinical staff)")
    license_type: Optional[str] = Field(None, description="Medical license type (MD, RN, NP, etc.)")
    employment_status: EmploymentStatus = EmploymentStatus.ACTIVE


# ─────────────────────────────────────────────────────────
# AUTHORIZATION BLOCK
# ─────────────────────────────────────────────────────────

class AuthorizationBlock(BaseModel):
    """Computed authorization envelope."""
    model_config = ConfigDict(frozen=True)
    direct_roles: list[str] = Field(default_factory=list, description="Roles from JWT")
    effective_roles: list[str] = Field(
        default_factory=list,
        description="Expanded roles after inheritance resolution (e.g., ATTENDING_PHYSICIAN → CLINICIAN → EMPLOYEE)"
    )
    groups: list[str] = Field(default_factory=list, description="Azure AD group memberships")
    domain: Domain = Field(..., description="Primary data domain")
    clearance_level: ClearanceLevel = Field(..., description="Max data sensitivity tier this user can access")
    sensitivity_cap: ClearanceLevel = Field(
        ...,
        description="Effective cap — may be reduced from clearance_level if MFA is absent"
    )
    bound_policies: list[str] = Field(default_factory=list, description="Policy IDs bound to this role")


# ─────────────────────────────────────────────────────────
# REQUEST METADATA BLOCK
# ─────────────────────────────────────────────────────────

class RequestMetadataBlock(BaseModel):
    """Request origin and timing metadata."""
    model_config = ConfigDict(frozen=True)
    ip_address: str = "0.0.0.0"
    user_agent: Optional[str] = None
    timestamp: datetime
    session_id: str = Field(..., description="Server-generated session identifier")


# ─────────────────────────────────────────────────────────
# EMERGENCY (BREAK-THE-GLASS) BLOCK
# ─────────────────────────────────────────────────────────

class EmergencyBlock(BaseModel):
    """Break-the-Glass (BTG) state."""
    model_config = ConfigDict(frozen=True)
    mode: EmergencyMode = EmergencyMode.NONE
    reason: Optional[str] = None
    patient_id: Optional[str] = Field(None, description="Patient ID that triggered BTG (audit trail)")
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    original_clearance: Optional[ClearanceLevel] = None


# ─────────────────────────────────────────────────────────
# FULL SECURITY CONTEXT
# ─────────────────────────────────────────────────────────

class SecurityContext(BaseModel):
    """
    The complete security context — primary output of L1.

    This object is:
      1. Built by context_builder.py
      2. Signed via HMAC-SHA256 by signing.py
      3. Stored in Redis by redis_store.py
      4. Consumed by L2–L8 on every NL-to-SQL request

    TTL:
      Normal  = 900 seconds  (15 min)
      BTG     = 14400 seconds (4 hours)

    FROZEN: All fields are immutable after construction.
    This prevents post-signing tampering within the process boundary.
    BTG escalation creates a NEW SecurityContext object rather than mutating.
    """
    model_config = ConfigDict(frozen=True)
    ctx_id: str = Field(..., description="Unique context token (ctx_<uuid>)")
    version: str = Field(default="2.0", description="SecurityContext schema version")
    identity: IdentityBlock
    org_context: OrgContextBlock
    authorization: AuthorizationBlock
    request_metadata: RequestMetadataBlock
    emergency: EmergencyBlock = Field(default_factory=lambda: EmergencyBlock())
    ttl_seconds: int = Field(default=900)
    created_at: datetime
    expires_at: datetime
