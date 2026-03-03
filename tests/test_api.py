"""Tests -- API integration (routes.py + full pipeline)"""

import pytest


class TestHealth:

    def test_health_check(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"
        assert data["version"] == "2.0.0"
        assert "mock_idp_enabled" in data


class TestResolveSecurityContext:
    """POST /resolve-security-context"""

    def test_resolve_success(self, client, valid_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r.status_code == 200
        data = r.json()

        # Top-level response fields
        assert data["ctx_token"].startswith("ctx_")
        assert len(data["signature"]) == 64
        assert data["expires_in"] == 900

        # Context preview
        preview = data["context_preview"]
        assert preview["oid"] == "oid-dr-patel-4521"
        assert preview["name"] == "Dr. Rajesh Patel"
        assert preview["department"] == "Cardiology"
        assert preview["domain"] == "CLINICAL"
        assert "ATTENDING_PHYSICIAN" in preview["direct_roles"]
        assert preview["clearance_level"] == 4
        assert preview["sensitivity_cap"] == 4
        assert preview["mfa_verified"] is True
        assert preview["emergency_mode"] == "NONE"

    def test_resolve_includes_effective_roles(self, client, valid_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        preview = r.json()["context_preview"]
        effective = preview["effective_roles"]
        assert "ATTENDING_PHYSICIAN" in effective
        assert "SENIOR_CLINICIAN" in effective
        assert "CLINICIAN" in effective
        assert "EMPLOYEE" in effective

    def test_resolve_no_mfa_reduces_cap(self, client, token_no_mfa):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {token_no_mfa}"},
        )
        assert r.status_code == 200
        preview = r.json()["context_preview"]
        assert preview["clearance_level"] == 4
        assert preview["sensitivity_cap"] == 3  # reduced by 1
        assert preview["mfa_verified"] is False

    def test_resolve_billing_clerk(self, client, billing_clerk_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {billing_clerk_token}"},
        )
        assert r.status_code == 200
        preview = r.json()["context_preview"]
        assert preview["domain"] == "FINANCIAL"
        assert preview["clearance_level"] == 2
        assert "BILLING_CLERK" in preview["direct_roles"]

    def test_resolve_psychiatrist(self, client, psychiatrist_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {psychiatrist_token}"},
        )
        assert r.status_code == 200
        preview = r.json()["context_preview"]
        assert preview["clearance_level"] == 5  # RESTRICTED
        assert preview["domain"] == "CLINICAL"

    def test_resolve_expired_token_401(self, client, expired_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert r.status_code == 401

    def test_resolve_wrong_audience_401(self, client, wrong_audience_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {wrong_audience_token}"},
        )
        assert r.status_code == 401

    def test_resolve_wrong_issuer_401(self, client, wrong_issuer_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {wrong_issuer_token}"},
        )
        assert r.status_code == 401

    def test_resolve_invalid_signature_401(self, client, invalid_signature_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {invalid_signature_token}"},
        )
        assert r.status_code == 401
        assert "Invalid signature" in r.json().get("detail", "")

    def test_external_file_signed_token(self, client):
        """Manually sign a payload using the provided private key file and
        ensure the service validates it (static key path logic)."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend
        from app.config import get_settings
        import jwt, time, uuid

        # load private key from file (same that settings point to)
        with open("app/keys/knk_private.pem", "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

        now = int(time.time())
        payload = {
            "oid": "oid-dr-patel-4521",
            "sub": "oid-dr-patel-4521",
            "name": "Dr. Rajesh Patel",
            "preferred_username": "dr.patel@apollohospitals.com",
            "email": "dr.patel@apollohospitals.com",
            "roles": ["ATTENDING_PHYSICIAN"],
            "groups": ["clinical-cardiology"],
            "amr": ["pwd", "mfa"],
            "jti": str(uuid.uuid4()),
            "iss": get_settings().AZURE_ISSUER,
            "aud": get_settings().AZURE_CLIENT_ID,
            "iat": now,
            "nbf": now,
            "exp": now + 3600,
        }
        token = jwt.encode(payload, priv, algorithm="RS256", headers={"kid": "mock-key-1"})

        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

    def test_resolve_no_bearer_prefix_401(self, client, valid_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": valid_token},
        )
        assert r.status_code == 401

    def test_resolve_no_auth_header_422(self, client):
        # with HTTPBearer security the missing header yields 401 Unauthorized
        r = client.post("/resolve-security-context")
        assert r.status_code == 401


class TestBreakGlass:
    """POST /break-glass"""

    def _resolve(self, client, token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {token}"},
        )
        return r.json()["ctx_token"]

    def test_btg_success_er_physician(self, client, er_physician_token):
        ctx_token = self._resolve(client, er_physician_token)
        r = client.post(
            "/break-glass",
            json={
                "ctx_token": ctx_token,
                "reason": "Emergency cardiac arrest patient in ER bay 3, need full history immediately",
                "patient_id": "PAT-00042",
            },
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["emergency_mode"] == "ACTIVE"
        assert data["elevated_clearance"] == 5
        assert data["expires_in"] == 14400
        assert data["previous_clearance"] == 4

    def test_btg_blocked_for_billing_clerk(self, client, billing_clerk_token):
        ctx_token = self._resolve(client, billing_clerk_token)
        r = client.post(
            "/break-glass",
            json={
                "ctx_token": ctx_token,
                "reason": "I really need to see the patient data for billing purposes right now",
            },
            headers={"Authorization": f"Bearer {billing_clerk_token}"},
        )
        assert r.status_code == 403
        assert "BTG-eligible" in r.json()["detail"]

    def test_btg_short_reason_rejected(self, client, er_physician_token):
        ctx_token = self._resolve(client, er_physician_token)
        r = client.post(
            "/break-glass",
            json={
                "ctx_token": ctx_token,
                "reason": "emergency",
            },
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r.status_code == 422  # Pydantic validation

    def test_btg_unknown_ctx_404(self, client, er_physician_token):
        r = client.post(
            "/break-glass",
            json={
                "ctx_token": "ctx_nonexistent",
                "reason": "Emergency patient needs full records access immediately for treatment",
            },
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r.status_code == 404

    def test_btg_double_activation_409(self, client, er_physician_token):
        ctx_token = self._resolve(client, er_physician_token)
        # First activation
        r1 = client.post(
            "/break-glass",
            json={
                "ctx_token": ctx_token,
                "reason": "Emergency cardiac arrest patient in ER bay 3, need full history immediately",
            },
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r1.status_code == 200

        # Second activation on same context
        r2 = client.post(
            "/break-glass",
            json={
                "ctx_token": ctx_token,
                "reason": "Another emergency on the same session context needs escalation right now",
            },
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r2.status_code == 409


class TestRevoke:
    """POST /revoke"""

    def test_revoke_success(self, client, valid_token):
        # First resolve
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        ctx_token = r.json()["ctx_token"]

        # Revoke (must pass same JWT for ownership check)
        r2 = client.post(
            "/revoke",
            json={"ctx_token": ctx_token},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r2.status_code == 200
        assert r2.json()["revoked"] is True

    def test_revoke_nonexistent(self, client, valid_token):
        # Nonexistent context — ownership check skipped (ctx is None), revoke returns False
        r = client.post(
            "/revoke",
            json={"ctx_token": "ctx_doesnotexist"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r.status_code == 200
        assert r.json()["revoked"] is False


class TestMockTokenEndpoint:
    """POST /mock/token"""

    def test_generate_mock_token(self, client):
        r = client.post("/mock/token", params={
            "oid": "oid-nurse-kumar-2847",
            "name": "Anita Kumar",
            "email": "anita.kumar@apollohospitals.com",
            "include_mfa": True,
        })
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert data["payload"]["oid"] == "oid-nurse-kumar-2847"

        # Verify the generated token works end-to-end
        token = data["token"]
        r2 = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r2.status_code == 200


class TestUnknownUserDenied:
    """C1: Zero-trust — unknown OIDs must be rejected."""

    def test_unknown_oid_rejected_403(self, client, unknown_user_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {unknown_user_token}"},
        )
        assert r.status_code == 403
        assert "not found in the organisational directory" in r.json()["detail"]


class TestInactiveEmployeeDenied:
    """M6: Terminated employees must be blocked."""

    def test_terminated_employee_rejected_403(self, client, terminated_employee_token):
        r = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {terminated_employee_token}"},
        )
        assert r.status_code == 403
        assert "TERMINATED" in r.json()["detail"]


class TestJTIReplayAttack:
    """M5: After revocation, the same JWT must not be reusable."""

    def test_jti_replay_blocked_after_revoke(self, client, valid_token):
        # Step 1: Resolve — should succeed
        r1 = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r1.status_code == 200
        ctx_token = r1.json()["ctx_token"]

        # Step 2: Revoke — blacklists the JTI
        r2 = client.post(
            "/revoke",
            json={"ctx_token": ctx_token},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r2.status_code == 200
        assert r2.json()["revoked"] is True

        # Step 3: Replay the SAME JWT — must be rejected (JTI blacklisted)
        r3 = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert r3.status_code == 401
        assert "revoked" in r3.json()["detail"].lower() or "blacklist" in r3.json()["detail"].lower()


class TestBTGOwnershipEnforced:
    """BTG with stolen ctx_token from a different user — must be blocked."""

    def test_btg_wrong_owner_rejected(self, client, er_physician_token, billing_clerk_token):
        # ER physician creates a context
        r1 = client.post(
            "/resolve-security-context",
            headers={"Authorization": f"Bearer {er_physician_token}"},
        )
        assert r1.status_code == 200
        er_ctx = r1.json()["ctx_token"]

        # Billing clerk tries BTG on ER physician's context → 403 ownership mismatch
        r2 = client.post(
            "/break-glass",
            json={
                "ctx_token": er_ctx,
                "reason": "Emergency patient needs full records access immediately for billing",
            },
            headers={"Authorization": f"Bearer {billing_clerk_token}"},
        )
        assert r2.status_code == 403
        assert "does not match" in r2.json()["detail"]
