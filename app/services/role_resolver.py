"""
role_resolver.py — Role Inheritance & Clearance Resolution
==========================================================

Implements a mock Neo4j-style directed acyclic graph (DAG) for role inheritance.

In production, this would execute Cypher:
    MATCH (r:Role {name: $role})-[:INHERITS_FROM*]->(parent:Role)
    RETURN collect(parent.name) AS ancestors

For the MVP, the inheritance tree and clearance mappings are hardcoded
from the Apollo Hospitals RBAC specification.

Key concepts:
  - Direct roles:    Roles directly assigned to the user (from JWT)
  - Effective roles: Direct roles + all inherited ancestor roles
  - Clearance:       Max data sensitivity tier (1–5) mapped from role
  - Sensitivity cap: Effective clearance after MFA check (no MFA → reduced)
  - Domain:          Primary data domain boundary (Clinical, Financial, etc.)
  - Bound policies:  Policy IDs that apply to the role set
"""

from __future__ import annotations
import logging
from dataclasses import dataclass, field

from app.models.enums import ClearanceLevel, Domain

logger = logging.getLogger("l1.role_resolver")


# ─────────────────────────────────────────────────────────
# ROLE INHERITANCE GRAPH (mock Neo4j)
# ─────────────────────────────────────────────────────────
# Format:  ROLE → [PARENT_1, PARENT_2, ...]
# Read as: "ROLE inherits from PARENT_1 and PARENT_2"

ROLE_INHERITANCE: dict[str, list[str]] = {
    # ── Clinical hierarchy ──
    "ATTENDING_PHYSICIAN":     ["SENIOR_CLINICIAN"],
    "CONSULTING_PHYSICIAN":    ["CLINICIAN"],
    "EMERGENCY_PHYSICIAN":     ["SENIOR_CLINICIAN", "EMERGENCY_RESPONDER"],
    "PSYCHIATRIST":            ["SENIOR_CLINICIAN", "RESTRICTED_DATA_HANDLER"],
    "RESIDENT":                ["CLINICIAN"],
    "SENIOR_CLINICIAN":        ["CLINICIAN"],
    "CLINICIAN":               ["HEALTHCARE_PROVIDER", "HIPAA_COVERED_ENTITY"],
    "HEALTHCARE_PROVIDER":     ["EMPLOYEE"],

    # ── Nursing hierarchy ──
    "HEAD_NURSE":              ["SENIOR_NURSE"],
    "ICU_NURSE":               ["SENIOR_NURSE"],
    "SENIOR_NURSE":            ["REGISTERED_NURSE"],
    "REGISTERED_NURSE":        ["NURSING_STAFF"],
    "NURSING_STAFF":           ["HEALTHCARE_PROVIDER", "HIPAA_COVERED_ENTITY"],

    # ── Business / Revenue ──
    "REVENUE_CYCLE_MANAGER":   ["FINANCE_STAFF"],
    "REVENUE_CYCLE_ANALYST":   ["FINANCE_STAFF"],
    "BILLING_CLERK":           ["FINANCE_STAFF"],
    "FINANCE_STAFF":           ["BUSINESS_STAFF", "HIPAA_COVERED_ENTITY"],
    "BUSINESS_STAFF":          ["EMPLOYEE"],

    # ── Administrative ──
    "HR_DIRECTOR":             ["HR_STAFF", "SENSITIVE_DATA_HANDLER"],
    "HR_MANAGER":              ["HR_STAFF"],
    "HR_STAFF":                ["ADMIN_STAFF"],
    "ADMIN_STAFF":             ["EMPLOYEE"],

    # ── IT ──
    "IT_ADMINISTRATOR":        ["IT_STAFF"],
    "IT_STAFF":                ["EMPLOYEE"],

    # ── Compliance ──
    "HIPAA_PRIVACY_OFFICER":   ["COMPLIANCE_STAFF", "AUDIT_REVIEWER", "RESTRICTED_DATA_HANDLER"],
    "COMPLIANCE_STAFF":        ["EMPLOYEE"],

    # ── Research ──
    "CLINICAL_RESEARCHER":     ["RESEARCH_STAFF", "HIPAA_COVERED_ENTITY"],
    "RESEARCH_STAFF":          ["EMPLOYEE"],

    # ── Base / abstract roles (no parents) ──
    "EMPLOYEE":                [],
    "HIPAA_COVERED_ENTITY":    [],
    "EMERGENCY_RESPONDER":     [],
    "RESTRICTED_DATA_HANDLER": [],
    "SENSITIVE_DATA_HANDLER":  [],
    "AUDIT_REVIEWER":          [],
}


# ─────────────────────────────────────────────────────────
# ROLE → CLEARANCE LEVEL MAPPING
# ─────────────────────────────────────────────────────────

ROLE_CLEARANCE: dict[str, ClearanceLevel] = {
    # Level 5 — Restricted
    "PSYCHIATRIST":            ClearanceLevel.RESTRICTED,
    "HIPAA_PRIVACY_OFFICER":   ClearanceLevel.RESTRICTED,

    # Level 4 — Highly Confidential
    "ATTENDING_PHYSICIAN":     ClearanceLevel.HIGHLY_CONFIDENTIAL,
    "EMERGENCY_PHYSICIAN":     ClearanceLevel.HIGHLY_CONFIDENTIAL,
    "HR_DIRECTOR":             ClearanceLevel.HIGHLY_CONFIDENTIAL,
    "SENIOR_CLINICIAN":        ClearanceLevel.HIGHLY_CONFIDENTIAL,

    # Level 3 — Confidential
    "CONSULTING_PHYSICIAN":    ClearanceLevel.CONFIDENTIAL,
    "RESIDENT":                ClearanceLevel.CONFIDENTIAL,
    "HEAD_NURSE":              ClearanceLevel.CONFIDENTIAL,
    "ICU_NURSE":               ClearanceLevel.CONFIDENTIAL,
    "HR_MANAGER":              ClearanceLevel.CONFIDENTIAL,
    "SENIOR_NURSE":            ClearanceLevel.CONFIDENTIAL,

    # Level 2 — Internal
    "REGISTERED_NURSE":        ClearanceLevel.INTERNAL,
    "BILLING_CLERK":           ClearanceLevel.INTERNAL,
    "REVENUE_CYCLE_ANALYST":   ClearanceLevel.INTERNAL,
    "REVENUE_CYCLE_MANAGER":   ClearanceLevel.INTERNAL,
    "IT_ADMINISTRATOR":        ClearanceLevel.INTERNAL,
    "CLINICAL_RESEARCHER":     ClearanceLevel.INTERNAL,

    # Level 1 — Public (fallback for unknown roles)
    "EMPLOYEE":                ClearanceLevel.PUBLIC,
}

# MFA_REDUCTION: clearance is reduced by this many levels if MFA is absent
MFA_ABSENT_REDUCTION = 1


# ─────────────────────────────────────────────────────────
# ROLE → DOMAIN MAPPING
# ─────────────────────────────────────────────────────────

ROLE_DOMAIN: dict[str, Domain] = {
    "ATTENDING_PHYSICIAN":     Domain.CLINICAL,
    "CONSULTING_PHYSICIAN":    Domain.CLINICAL,
    "EMERGENCY_PHYSICIAN":     Domain.CLINICAL,
    "PSYCHIATRIST":            Domain.CLINICAL,
    "RESIDENT":                Domain.CLINICAL,
    "HEAD_NURSE":              Domain.CLINICAL,
    "ICU_NURSE":               Domain.CLINICAL,
    "REGISTERED_NURSE":        Domain.CLINICAL,

    "BILLING_CLERK":           Domain.FINANCIAL,
    "REVENUE_CYCLE_ANALYST":   Domain.FINANCIAL,
    "REVENUE_CYCLE_MANAGER":   Domain.FINANCIAL,

    "HR_MANAGER":              Domain.ADMINISTRATIVE,
    "HR_DIRECTOR":             Domain.ADMINISTRATIVE,

    "IT_ADMINISTRATOR":        Domain.IT_OPERATIONS,

    "HIPAA_PRIVACY_OFFICER":   Domain.COMPLIANCE,

    "CLINICAL_RESEARCHER":     Domain.RESEARCH,
}


# ─────────────────────────────────────────────────────────
# ROLE → POLICY BINDING
# ─────────────────────────────────────────────────────────

ROLE_POLICIES: dict[str, list[str]] = {
    "ATTENDING_PHYSICIAN":     ["CLIN-001", "HIPAA-001"],
    "CONSULTING_PHYSICIAN":    ["CLIN-001", "HIPAA-001"],
    "EMERGENCY_PHYSICIAN":     ["CLIN-001", "HIPAA-001", "BTG-001"],
    "PSYCHIATRIST":            ["CLIN-001", "HIPAA-001", "CFR42-001"],
    "RESIDENT":                ["CLIN-001", "HIPAA-001"],
    "HEAD_NURSE":              ["CLIN-002", "HIPAA-001"],
    "ICU_NURSE":               ["CLIN-002", "HIPAA-001"],
    "REGISTERED_NURSE":        ["CLIN-002", "HIPAA-001"],
    "BILLING_CLERK":           ["BIZ-001", "HIPAA-001", "SEC-002"],
    "REVENUE_CYCLE_ANALYST":   ["BIZ-001", "HIPAA-001"],
    "REVENUE_CYCLE_MANAGER":   ["BIZ-001", "HIPAA-001"],
    "HR_MANAGER":              ["HR-001", "SEC-003"],
    "HR_DIRECTOR":             ["HR-001", "HR-002", "SEC-003"],
    "IT_ADMINISTRATOR":        ["IT-001"],
    "HIPAA_PRIVACY_OFFICER":   ["COMP-001", "HIPAA-001", "AUDIT-001"],
    "CLINICAL_RESEARCHER":     ["RES-001", "HIPAA-001"],
}


# ─────────────────────────────────────────────────────────
# RESOLVER OUTPUT
# ─────────────────────────────────────────────────────────

@dataclass
class ResolvedRoles:
    """Output of role resolution — everything authorization-related."""
    direct_roles: list[str]
    effective_roles: list[str]
    domain: Domain
    clearance_level: ClearanceLevel
    sensitivity_cap: ClearanceLevel
    bound_policies: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────
# ROLE RESOLVER
# ─────────────────────────────────────────────────────────

class RoleResolver:
    """
    Expands direct roles into effective roles via inheritance,
    computes clearance level, applies MFA-based sensitivity cap.

    Mock Neo4j pattern:
        Given role ATTENDING_PHYSICIAN, walk the DAG:
          ATTENDING_PHYSICIAN → SENIOR_CLINICIAN → CLINICIAN
            → HEALTHCARE_PROVIDER → EMPLOYEE
            → HIPAA_COVERED_ENTITY
        Effective roles = all visited nodes.
    """

    def resolve(self, direct_roles: list[str], mfa_verified: bool) -> ResolvedRoles:
        """
        Resolve the full authorization envelope from direct roles.

        Args:
            direct_roles:  Role names from the JWT (e.g., ["ATTENDING_PHYSICIAN"])
            mfa_verified:  True if the user authenticated with MFA

        Returns:
            ResolvedRoles with effective_roles, clearance, sensitivity_cap, domain, policies
        """
        # ── 1. Normalise role names ──
        normalised = [self._normalise(r) for r in direct_roles]

        # ── 2. Expand inheritance (BFS over DAG) ──
        effective = set()
        for role in normalised:
            effective.update(self._expand_role(role))

        effective_list = sorted(effective)

        # ── 3. Compute clearance (max across all effective roles) ──
        clearance = self._compute_clearance(effective)

        # ── 4. Apply MFA cap ──
        sensitivity_cap = self._apply_mfa_cap(clearance, mfa_verified)

        # ── 5. Determine primary domain ──
        domain = self._determine_domain(normalised)

        # ── 6. Collect bound policies ──
        policies = self._collect_policies(normalised)

        logger.info(
            "Roles resolved | direct=%s effective_count=%d clearance=%d cap=%d domain=%s",
            normalised, len(effective_list), clearance, sensitivity_cap, domain.value,
        )

        return ResolvedRoles(
            direct_roles=normalised,
            effective_roles=effective_list,
            domain=domain,
            clearance_level=clearance,
            sensitivity_cap=sensitivity_cap,
            bound_policies=policies,
        )

    # ── Internal helpers ──

    @staticmethod
    def _normalise(role: str) -> str:
        """Normalise role name: strip, uppercase, replace spaces/hyphens with underscores."""
        return role.strip().upper().replace(" ", "_").replace("-", "_")

    def _expand_role(self, role: str) -> set[str]:
        """BFS expansion: walk the inheritance DAG and collect all ancestors."""
        visited: set[str] = set()
        queue = [role]

        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            parents = ROLE_INHERITANCE.get(current, [])
            queue.extend(parents)

        return visited

    @staticmethod
    def _compute_clearance(effective_roles: set[str]) -> ClearanceLevel:
        """Max clearance across all effective roles."""
        max_level = ClearanceLevel.PUBLIC
        for role in effective_roles:
            level = ROLE_CLEARANCE.get(role, ClearanceLevel.PUBLIC)
            if level > max_level:
                max_level = level
        return ClearanceLevel(max_level)

    @staticmethod
    def _apply_mfa_cap(clearance: ClearanceLevel, mfa_verified: bool) -> ClearanceLevel:
        """If MFA is absent, reduce sensitivity cap by MFA_ABSENT_REDUCTION.

        Example:
            Clearance 4 (Highly Confidential) + no MFA → cap at 3 (Confidential)
            Clearance 2 (Internal) + no MFA → cap at 1 (Public)

        This means without MFA, users cannot access data at their max clearance.
        """
        if mfa_verified:
            return clearance

        reduced = max(ClearanceLevel.PUBLIC, clearance - MFA_ABSENT_REDUCTION)
        logger.warning(
            "MFA absent — reducing sensitivity cap from %d to %d",
            clearance, reduced,
        )
        return ClearanceLevel(reduced)

    @staticmethod
    def _determine_domain(direct_roles: list[str]) -> Domain:
        """Determine primary domain from direct roles.
        First match wins — direct roles are in priority order."""
        for role in direct_roles:
            if role in ROLE_DOMAIN:
                return ROLE_DOMAIN[role]
        return Domain.CLINICAL  # safe default for healthcare

    @staticmethod
    def _collect_policies(direct_roles: list[str]) -> list[str]:
        """Collect de-duped policies bound to the direct roles."""
        policies: set[str] = set()
        for role in direct_roles:
            policies.update(ROLE_POLICIES.get(role, []))
        return sorted(policies)
