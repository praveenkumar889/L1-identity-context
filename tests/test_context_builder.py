"""Tests -- context_builder.py"""

import pytest
from app.services.context_builder import ContextBuilder, ContextBuildError
from app.dependencies import container


@pytest.fixture
def builder():
    """Get the initialised ContextBuilder from the service container."""
    if container.context_builder is None:
        container.initialise()
    return container.context_builder


class TestContextBuilder:

    def test_full_pipeline(self, builder, valid_token):
        ctx, sig = builder.resolve(valid_token, ip_address="10.0.0.1")

        # SecurityContext structure
        assert ctx.ctx_id.startswith("ctx_")
        assert ctx.version == "2.0"
        assert ctx.ttl_seconds == 900

        # Identity
        assert ctx.identity.oid == "oid-dr-patel-4521"
        assert ctx.identity.name == "Dr. Rajesh Patel"
        assert ctx.identity.mfa_verified is True

        # Org context (from mock enrichment)
        assert ctx.org_context.employee_id == "DR-0001"
        assert ctx.org_context.department == "Cardiology"
        assert "FAC-001" in ctx.org_context.facility_ids
        assert ctx.org_context.provider_npi == "NPI-1234567890"
        assert ctx.org_context.license_type == "MD"

        # Authorization
        assert ctx.authorization.clearance_level == 4
        assert ctx.authorization.sensitivity_cap == 4
        assert ctx.authorization.domain.value == "CLINICAL"
        assert "CLIN-001" in ctx.authorization.bound_policies

        # Emergency
        assert ctx.emergency.mode.value == "NONE"

        # Signature
        assert len(sig) == 64

    def test_expired_token_raises(self, builder, expired_token):
        with pytest.raises(ContextBuildError) as exc_info:
            builder.resolve(expired_token)
        assert exc_info.value.status_code == 401

    def test_no_mfa_reduces_cap(self, builder, token_no_mfa):
        ctx, _ = builder.resolve(token_no_mfa)
        assert ctx.authorization.clearance_level == 4
        assert ctx.authorization.sensitivity_cap == 3

    def test_context_stored_in_redis(self, builder, valid_token):
        ctx, _ = builder.resolve(valid_token)
        store = container.redis_store
        retrieved = store.get_context(ctx.ctx_id)
        assert retrieved is not None
        assert retrieved.ctx_id == ctx.ctx_id

    def test_revoke_and_jti_blacklist(self, builder, valid_token):
        ctx, _ = builder.resolve(valid_token)
        jti = ctx.identity.jti

        # Revoke
        assert builder.revoke(ctx.ctx_id) is True

        # Context gone
        store = container.redis_store
        assert store.get_context(ctx.ctx_id) is None

        # JTI blacklisted
        assert store.is_jti_blacklisted(jti) is True

    def test_unknown_user_rejected(self, builder, mock_keypair):
        """C1: Unknown OIDs must be denied (zero-trust)."""
        from tests.conftest import _make_jwt
        unknown_token = _make_jwt(mock_keypair, {
            "oid": "oid-completely-unknown",
            "roles": ["EMPLOYEE"],
        })
        with pytest.raises(ContextBuildError) as exc_info:
            builder.resolve(unknown_token)
        assert exc_info.value.status_code == 403
        assert "not found" in exc_info.value.message.lower()

    def test_terminated_employee_rejected(self, builder, mock_keypair):
        """M6: Terminated employees must be blocked."""
        from tests.conftest import _make_jwt
        terminated_token = _make_jwt(mock_keypair, {
            "oid": "oid-terminated-user-9999",
            "roles": ["REGISTERED_NURSE"],
        })
        with pytest.raises(ContextBuildError) as exc_info:
            builder.resolve(terminated_token)
        assert exc_info.value.status_code == 403
        assert "TERMINATED" in exc_info.value.message
