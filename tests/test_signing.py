"""Tests -- signing.py"""

import pytest
from datetime import datetime, timedelta, timezone

from app.services.signing import SecurityContextSigner
from app.models import (
    SecurityContext, IdentityBlock, OrgContextBlock,
    AuthorizationBlock, RequestMetadataBlock, EmergencyBlock,
    ClearanceLevel, Domain, EmergencyMode, EmploymentStatus,
)


@pytest.fixture
def signer():
    return SecurityContextSigner()


@pytest.fixture
def sample_context():
    now = datetime.now(timezone.utc)
    return SecurityContext(
        ctx_id="ctx_test123",
        version="2.0",
        identity=IdentityBlock(
            oid="oid-dr-patel-4521",
            name="Dr. Rajesh Patel",
            email="dr.patel@apollohospitals.com",
            jti="jti-test-123",
            mfa_verified=True,
            auth_methods=["pwd", "mfa"],
        ),
        org_context=OrgContextBlock(
            employee_id="DR-0001",
            department="Cardiology",
            facility_ids=["FAC-001"],
            unit_ids=["UNIT-1A-APJH"],
            provider_npi="NPI-1234567890",
            license_type="MD",
            employment_status=EmploymentStatus.ACTIVE,
        ),
        authorization=AuthorizationBlock(
            direct_roles=["ATTENDING_PHYSICIAN"],
            effective_roles=["ATTENDING_PHYSICIAN", "CLINICIAN", "EMPLOYEE"],
            groups=["clinical-cardiology"],
            domain=Domain.CLINICAL,
            clearance_level=ClearanceLevel.HIGHLY_CONFIDENTIAL,
            sensitivity_cap=ClearanceLevel.HIGHLY_CONFIDENTIAL,
            bound_policies=["CLIN-001", "HIPAA-001"],
        ),
        request_metadata=RequestMetadataBlock(
            ip_address="10.0.0.1",
            user_agent="test",
            timestamp=now,
            session_id="ses_test123",
        ),
        emergency=EmergencyBlock(mode=EmergencyMode.NONE),
        ttl_seconds=900,
        created_at=now,
        expires_at=now + timedelta(seconds=900),
    )


class TestSigning:

    def test_sign_returns_hex_digest(self, signer, sample_context):
        sig = signer.sign(sample_context)
        assert len(sig) == 64  # SHA-256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in sig)

    def test_sign_is_deterministic(self, signer, sample_context):
        sig1 = signer.sign(sample_context)
        sig2 = signer.sign(sample_context)
        assert sig1 == sig2

    def test_verify_valid(self, signer, sample_context):
        sig = signer.sign(sample_context)
        assert signer.verify(sample_context, sig) is True

    def test_verify_tampered_signature(self, signer, sample_context):
        assert signer.verify(sample_context, "a" * 64) is False

    def test_different_contexts_different_signatures(self, signer, sample_context):
        sig1 = signer.sign(sample_context)

        # Create a modified context
        now = datetime.now(timezone.utc)
        modified = SecurityContext(
            ctx_id="ctx_different",
            version="2.0",
            identity=sample_context.identity,
            org_context=sample_context.org_context,
            authorization=sample_context.authorization,
            request_metadata=RequestMetadataBlock(
                ip_address="192.168.1.1",
                user_agent="different",
                timestamp=now,
                session_id="ses_different",
            ),
            emergency=EmergencyBlock(mode=EmergencyMode.NONE),
            ttl_seconds=900,
            created_at=now,
            expires_at=now + timedelta(seconds=900),
        )
        sig2 = signer.sign(modified)
        assert sig1 != sig2
