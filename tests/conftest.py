"""
Test Fixtures — Mock JWT generation, test client, service instances.
"""

import pytest
import time
import uuid
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def app():
    """FastAPI app instance."""
    from app.main import app
    return app


@pytest.fixture(scope="session")
def client(app):
    """Synchronous test client."""
    return TestClient(app)


@pytest.fixture(scope="session")
def mock_keypair():
    """Mock RSA keypair for signing test JWTs."""
    from app.services.token_validation import MockKeyPair
    return MockKeyPair.get()


def _make_jwt(mock_keypair, overrides: dict = None) -> str:
    """Helper: build a signed mock JWT with sensible defaults."""
    from app.config import get_settings
    settings = get_settings()
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
        "iss": settings.AZURE_ISSUER,
        "aud": settings.AZURE_CLIENT_ID,
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    if overrides:
        payload.update(overrides)
    return mock_keypair.sign_jwt(payload)


@pytest.fixture
def valid_token(mock_keypair):
    """A valid JWT for dr-patel-4521 (Attending Physician, clearance 4, with MFA)."""
    return _make_jwt(mock_keypair)


@pytest.fixture
def token_no_mfa(mock_keypair):
    """JWT without MFA — sensitivity cap should be reduced."""
    return _make_jwt(mock_keypair, {"amr": ["pwd"]})


@pytest.fixture
def expired_token(mock_keypair):
    """JWT that expired 1 hour ago."""
    now = int(time.time())
    return _make_jwt(mock_keypair, {"exp": now - 3600, "iat": now - 7200, "nbf": now - 7200})


@pytest.fixture
def wrong_audience_token(mock_keypair):
    """JWT with wrong audience."""
    return _make_jwt(mock_keypair, {"aud": "wrong-audience"})


@pytest.fixture
def wrong_issuer_token(mock_keypair):
    """JWT with wrong issuer."""
    return _make_jwt(mock_keypair, {"iss": "https://evil.example.com"})


@pytest.fixture
def er_physician_token(mock_keypair):
    """JWT for dr-reddy-2233 (Emergency Physician, BTG-eligible)."""
    return _make_jwt(mock_keypair, {
        "oid": "oid-dr-reddy-2233",
        "name": "Dr. Aditya Reddy",
        "preferred_username": "dr.reddy@apollohospitals.com",
        "roles": ["EMERGENCY_PHYSICIAN"],
        "groups": ["clinical-emergency"],
    })


@pytest.fixture
def billing_clerk_token(mock_keypair):
    """JWT for bill-maria-5521 (Billing Clerk, NOT BTG-eligible)."""
    return _make_jwt(mock_keypair, {
        "oid": "oid-bill-maria-5521",
        "name": "Maria Fernandes",
        "preferred_username": "maria.fernandes@apollohospitals.com",
        "roles": ["BILLING_CLERK"],
        "groups": ["finance-billing"],
    })


@pytest.fixture
def psychiatrist_token(mock_keypair):
    """JWT for dr-iyer-3301 (Psychiatrist, clearance 5)."""
    return _make_jwt(mock_keypair, {
        "oid": "oid-dr-iyer-3301",
        "name": "Dr. Meera Iyer",
        "preferred_username": "dr.iyer@apollohospitals.com",
        "roles": ["PSYCHIATRIST"],
        "groups": ["clinical-psychiatry"],
    })


@pytest.fixture
def terminated_employee_token(mock_keypair):
    """JWT for oid-terminated-user-9999 (TERMINATED employment status)."""
    return _make_jwt(mock_keypair, {
        "oid": "oid-terminated-user-9999",
        "name": "Terminated User",
        "preferred_username": "terminated@apollohospitals.com",
        "roles": ["REGISTERED_NURSE"],
        "groups": ["clinical-cardiology"],
    })


@pytest.fixture
def unknown_user_token(mock_keypair):
    """JWT for an OID that does NOT exist in the mock directory."""
    return _make_jwt(mock_keypair, {
        "oid": "oid-unknown-intruder-0000",
        "name": "Unknown Intruder",
        "preferred_username": "intruder@external.com",
        "roles": ["EMPLOYEE"],
        "groups": [],
    })
