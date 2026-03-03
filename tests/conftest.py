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
    """Synchronous test client.

    Use a context manager so FastAPI lifespan events are executed and the
    service container is initialised (startup/shutdown hooks).
    """
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Clear in-memory rate limiter before each test so tests don't interfere.

    Some API tests fire multiple BTG requests that cumulatively exceed the
    per-IP limit, causing unrelated tests to flake. Resetting the limiter
    ensures each test sees a clean slate.
    """
    from app.dependencies import container

    if getattr(container, "rate_limiter", None) is not None:
        container.rate_limiter._requests.clear()


@pytest.fixture(scope="session")
def mock_keypair():
    """Mock RSA keypair for signing test JWTs.

    The underlying keypair is loaded from `Settings.JWT_PRIVATE_KEY_PATH`
    if configured (the test harness sets this to the checked-in knk files)."""
    from app.services.token_validation import MockKeyPair
    return MockKeyPair.get()


@pytest.fixture(scope="session", autouse=True)
def configure_static_keys():
    """Point the application at the static key files that live under app/keys.

    This fixture runs before the TestClient is created so that the service
    initialisation picks up the correct files.  It also disables mock mode to
    prove the same keys are used regardless of MOCK_IDP_ENABLED.
    """
    from app.config import get_settings
    import os

    settings = get_settings()
    # set paths relative to project root
    settings.JWT_PRIVATE_KEY_PATH = os.path.join(os.getcwd(), "app/keys/knk_private.pem")
    settings.JWT_PUBLIC_KEY_PATH = os.path.join(os.getcwd(), "app/keys/knk.pem")
    # for clarity, leave MOCK_IDP_ENABLED whatever; the implementation prefers
    # explicit key paths over mock flag
    # ensure the mock endpoint is available during tests
    settings.MOCK_IDP_ENABLED = True
    # provide a dummy HMAC key to satisfy validate_for_startup
    if not settings.HMAC_SECRET_KEY:
        settings.HMAC_SECRET_KEY = "test-hmac-secret-key-0123456789abcdef"
    return


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
def invalid_signature_token(mock_keypair):
    """JWT signed with a different keypair to simulate signature mismatch."""
    # replicate base payload from _make_jwt without using mock_keypair
    from app.config import get_settings
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
    import time, uuid, jwt as pyjwt

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
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=settings.MOCK_IDP_RSA_KEY_SIZE, backend=default_backend())
    return pyjwt.encode(payload, other_key, algorithm="RS256", headers={"kid": "mock-key-1"})


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
