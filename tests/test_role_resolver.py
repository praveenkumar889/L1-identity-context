"""Tests — role_resolver.py"""

import pytest
from app.services.role_resolver import RoleResolver
from app.models.enums import ClearanceLevel, Domain


@pytest.fixture
def resolver():
    return RoleResolver()


class TestRoleInheritance:
    """Verify the mock Neo4j DAG expansion."""

    def test_attending_physician_expansion(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=True)
        assert "ATTENDING_PHYSICIAN" in result.effective_roles
        assert "SENIOR_CLINICIAN" in result.effective_roles
        assert "CLINICIAN" in result.effective_roles
        assert "HEALTHCARE_PROVIDER" in result.effective_roles
        assert "EMPLOYEE" in result.effective_roles
        assert "HIPAA_COVERED_ENTITY" in result.effective_roles

    def test_billing_clerk_expansion(self, resolver):
        result = resolver.resolve(["BILLING_CLERK"], mfa_verified=True)
        assert "BILLING_CLERK" in result.effective_roles
        assert "FINANCE_STAFF" in result.effective_roles
        assert "BUSINESS_STAFF" in result.effective_roles
        assert "EMPLOYEE" in result.effective_roles
        # Should NOT inherit clinical roles
        assert "CLINICIAN" not in result.effective_roles
        assert "HEALTHCARE_PROVIDER" not in result.effective_roles

    def test_emergency_physician_has_emergency_responder(self, resolver):
        result = resolver.resolve(["EMERGENCY_PHYSICIAN"], mfa_verified=True)
        assert "EMERGENCY_RESPONDER" in result.effective_roles
        assert "SENIOR_CLINICIAN" in result.effective_roles

    def test_psychiatrist_has_restricted_data_handler(self, resolver):
        result = resolver.resolve(["PSYCHIATRIST"], mfa_verified=True)
        assert "RESTRICTED_DATA_HANDLER" in result.effective_roles

    def test_hipaa_officer_has_audit_reviewer(self, resolver):
        result = resolver.resolve(["HIPAA_PRIVACY_OFFICER"], mfa_verified=True)
        assert "AUDIT_REVIEWER" in result.effective_roles
        assert "COMPLIANCE_STAFF" in result.effective_roles


class TestClearanceLevels:
    """Verify clearance mapping."""

    def test_attending_physician_clearance_4(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=True)
        assert result.clearance_level == ClearanceLevel.HIGHLY_CONFIDENTIAL  # 4

    def test_psychiatrist_clearance_5(self, resolver):
        result = resolver.resolve(["PSYCHIATRIST"], mfa_verified=True)
        assert result.clearance_level == ClearanceLevel.RESTRICTED  # 5

    def test_billing_clerk_clearance_2(self, resolver):
        result = resolver.resolve(["BILLING_CLERK"], mfa_verified=True)
        assert result.clearance_level == ClearanceLevel.INTERNAL  # 2

    def test_registered_nurse_clearance_2(self, resolver):
        result = resolver.resolve(["REGISTERED_NURSE"], mfa_verified=True)
        assert result.clearance_level == ClearanceLevel.INTERNAL  # 2

    def test_icu_nurse_clearance_3(self, resolver):
        result = resolver.resolve(["ICU_NURSE"], mfa_verified=True)
        assert result.clearance_level == ClearanceLevel.CONFIDENTIAL  # 3


class TestMFACap:
    """Verify MFA-based sensitivity cap reduction."""

    def test_mfa_present_no_reduction(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=True)
        assert result.clearance_level == 4
        assert result.sensitivity_cap == 4  # no reduction

    def test_mfa_absent_reduces_by_one(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=False)
        assert result.clearance_level == 4
        assert result.sensitivity_cap == 3  # reduced by 1

    def test_mfa_absent_floor_is_1(self, resolver):
        """Clearance 1 user without MFA should not go below 1."""
        result = resolver.resolve(["EMPLOYEE"], mfa_verified=False)
        assert result.sensitivity_cap == ClearanceLevel.PUBLIC  # floor at 1


class TestDomainMapping:
    """Verify role → domain mapping."""

    def test_physician_is_clinical(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=True)
        assert result.domain == Domain.CLINICAL

    def test_billing_is_financial(self, resolver):
        result = resolver.resolve(["BILLING_CLERK"], mfa_verified=True)
        assert result.domain == Domain.FINANCIAL

    def test_hr_is_administrative(self, resolver):
        result = resolver.resolve(["HR_MANAGER"], mfa_verified=True)
        assert result.domain == Domain.ADMINISTRATIVE

    def test_researcher_is_research(self, resolver):
        result = resolver.resolve(["CLINICAL_RESEARCHER"], mfa_verified=True)
        assert result.domain == Domain.RESEARCH


class TestPolicyBinding:
    """Verify role → policy binding."""

    def test_attending_physician_policies(self, resolver):
        result = resolver.resolve(["ATTENDING_PHYSICIAN"], mfa_verified=True)
        assert "CLIN-001" in result.bound_policies
        assert "HIPAA-001" in result.bound_policies

    def test_billing_clerk_policies(self, resolver):
        result = resolver.resolve(["BILLING_CLERK"], mfa_verified=True)
        assert "BIZ-001" in result.bound_policies
        assert "HIPAA-001" in result.bound_policies
        assert "SEC-002" in result.bound_policies

    def test_emergency_physician_has_btg_policy(self, resolver):
        result = resolver.resolve(["EMERGENCY_PHYSICIAN"], mfa_verified=True)
        assert "BTG-001" in result.bound_policies


class TestNormalisation:
    """Verify role name normalisation."""

    def test_lowercase_normalised(self, resolver):
        result = resolver.resolve(["attending_physician"], mfa_verified=True)
        assert "ATTENDING_PHYSICIAN" in result.direct_roles

    def test_hyphen_normalised(self, resolver):
        result = resolver.resolve(["attending-physician"], mfa_verified=True)
        assert "ATTENDING_PHYSICIAN" in result.direct_roles
