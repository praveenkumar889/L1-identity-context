"""
user_enrichment.py — Mock HR/LDAP User Context Enrichment
==========================================================

In production, this would call:
  - Azure AD Graph API for group memberships
  - HR system (Workday/SAP) for employee_id, department, NPI
  - Facility management system for unit assignments

For the MVP, returns hardcoded org context for the 15 Apollo test users.
Unknown users get a safe default (minimal access).
"""

from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Optional

from app.models.enums import EmploymentStatus

logger = logging.getLogger("l1.user_enrichment")


@dataclass
class EnrichedUserContext:
    """Org context returned by the mock HR system."""
    employee_id: str
    department: str
    facility_ids: list[str]
    unit_ids: list[str]
    provider_npi: Optional[str]
    license_type: Optional[str]
    employment_status: EmploymentStatus


# ─────────────────────────────────────────────────────────
# MOCK USER DIRECTORY  (15 Apollo test users)
# ─────────────────────────────────────────────────────────
# Keyed by Azure AD oid (in production, this is the Object ID)

MOCK_DIRECTORY: dict[str, EnrichedUserContext] = {
    # ── Physicians ──
    "oid-dr-patel-4521": EnrichedUserContext(
        employee_id="DR-0001",
        department="Cardiology",
        facility_ids=["FAC-001"],
        unit_ids=["UNIT-1A-APJH", "UNIT-1B-APJH"],
        provider_npi="NPI-1234567890",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-sharma-1102": EnrichedUserContext(
        employee_id="DR-0002",
        department="Oncology",
        facility_ids=["FAC-002"],
        unit_ids=["UNIT-3A-IPAH", "UNIT-3B-IPAH"],
        provider_npi="NPI-2345678901",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-reddy-2233": EnrichedUserContext(
        employee_id="DR-0003",
        department="Emergency Medicine",
        facility_ids=["FAC-003"],
        unit_ids=["UNIT-ER-APGR", "UNIT-MICU-APGR"],
        provider_npi="NPI-3456789012",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-dr-iyer-3301": EnrichedUserContext(
        employee_id="DR-0004",
        department="Psychiatry",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi="NPI-4567890123",
        license_type="MD",
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── Nurses ──
    "oid-nurse-kumar-2847": EnrichedUserContext(
        employee_id="EMP-0151",
        department="Cardiology",
        facility_ids=["FAC-001"],
        unit_ids=["UNIT-1A-APJH", "UNIT-1B-APJH"],
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-nurse-nair-3102": EnrichedUserContext(
        employee_id="EMP-0160",
        department="Emergency Medicine",
        facility_ids=["FAC-003"],
        unit_ids=["UNIT-MICU-APGR"],
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-nurse-singh-4455": EnrichedUserContext(
        employee_id="EMP-0165",
        department="Neurology",
        facility_ids=["FAC-002"],
        unit_ids=["UNIT-2A-IPAH", "UNIT-2B-IPAH"],
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── Billing / Revenue ──
    "oid-bill-maria-5521": EnrichedUserContext(
        employee_id="EMP-0301",
        department="Billing & Revenue Cycle",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-bill-suresh-5530": EnrichedUserContext(
        employee_id="EMP-0305",
        department="Billing & Revenue Cycle",
        facility_ids=["FAC-002"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-rev-james-6601": EnrichedUserContext(
        employee_id="EMP-0310",
        department="Billing & Revenue Cycle",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── HR ──
    "oid-hr-priya-7701": EnrichedUserContext(
        employee_id="EMP-0351",
        department="Human Resources",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),
    "oid-hr-dir-kapoor": EnrichedUserContext(
        employee_id="EMP-0355",
        department="Human Resources",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── IT ──
    "oid-it-admin-7801": EnrichedUserContext(
        employee_id="EMP-0371",
        department="Information Technology",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── Compliance ──
    "oid-hipaa-officer": EnrichedUserContext(
        employee_id="EMP-0381",
        department="Compliance & Legal",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── Research ──
    "oid-researcher-das": EnrichedUserContext(
        employee_id="EMP-0391",
        department="Quality Assurance",
        facility_ids=["FAC-005"],
        unit_ids=[],
        provider_npi=None,
        license_type=None,
        employment_status=EmploymentStatus.ACTIVE,
    ),

    # ── Inactive test user (TERMINATED — used to verify employment status enforcement) ──
    "oid-terminated-user-9999": EnrichedUserContext(
        employee_id="EMP-0999",
        department="Cardiology",
        facility_ids=["FAC-001"],
        unit_ids=[],
        provider_npi=None,
        license_type="RN",
        employment_status=EmploymentStatus.TERMINATED,
    ),
}


class UserEnrichmentService:
    """
    Enriches a validated JWT identity with organisational context.

    In production this calls:
      1. Azure AD Graph API → group memberships
      2. HR System (Workday/SAP) → employee_id, department, NPI
      3. Facility Management → unit_ids, facility_ids

    For the MVP, returns hardcoded data for 15 Apollo users.
    """

    def enrich(self, oid: str) -> EnrichedUserContext:
        """
        Look up org context by Azure AD Object ID.

        Args:
            oid: The user's Azure AD oid (from JWT)

        Returns:
            EnrichedUserContext with HR/org data

        Raises:
            UnknownUserError: If oid is not found in the directory (zero-trust deny-by-default)
            InactiveEmployeeError: If the user's employment status is not ACTIVE
        """
        ctx = MOCK_DIRECTORY.get(oid)
        if ctx is None:
            logger.warning(
                "ACCESS DENIED — unknown user not in directory | oid=%s", oid,
            )
            raise UnknownUserError(
                f"User {oid} not found in the organisational directory. "
                f"Zero-trust policy: unknown identities are denied by default."
            )

        if ctx.employment_status != EmploymentStatus.ACTIVE:
            logger.warning(
                "ACCESS DENIED — non-active employment status | oid=%s status=%s",
                oid, ctx.employment_status.value,
            )
            raise InactiveEmployeeError(
                f"User {oid} has employment status: {ctx.employment_status.value}. "
                f"Only ACTIVE employees may authenticate."
            )

        logger.info(
            "User enriched | oid=%s emp=%s dept=%s facilities=%s",
            oid, ctx.employee_id, ctx.department, ctx.facility_ids,
        )
        return ctx


class UnknownUserError(Exception):
    """Raised when an OID is not found in the organisational directory.
    Zero-trust: deny unknown identities by default."""
    pass


class InactiveEmployeeError(Exception):
    """Raised when a non-ACTIVE employee attempts to authenticate."""
    pass
