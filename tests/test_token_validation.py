"""Tests — token_validation.py"""

import pytest
from app.services.token_validation import TokenValidator, TokenValidationError


@pytest.fixture
def validator():
    return TokenValidator()


def test_valid_token(validator, valid_token):
    claims = validator.validate(valid_token)
    assert claims.oid == "oid-dr-patel-4521"
    assert claims.name == "Dr. Rajesh Patel"
    assert claims.email == "dr.patel@apollohospitals.com"
    assert "ATTENDING_PHYSICIAN" in claims.roles
    assert "mfa" in claims.amr
    assert claims.jti != ""


def test_expired_token_rejected(validator, expired_token):
    with pytest.raises(TokenValidationError, match="expired"):
        validator.validate(expired_token)


def test_wrong_audience_rejected(validator, wrong_audience_token):
    with pytest.raises(TokenValidationError, match="audience"):
        validator.validate(wrong_audience_token)


def test_wrong_issuer_rejected(validator, wrong_issuer_token):
    with pytest.raises(TokenValidationError, match="issuer"):
        validator.validate(wrong_issuer_token)


def test_garbage_token_rejected(validator):
    with pytest.raises(TokenValidationError):
        validator.validate("not.a.real.jwt")


def test_static_keypath_skips_jwks(monkeypatch, validator, valid_token):
    """When a public key path is configured we must never hit the JWKS client."""
    from app.config import get_settings
    from app.services import token_validation as tv

    settings = get_settings()
    # ensure path is set (already done by autouse fixture) but double-check
    assert settings.JWT_PUBLIC_KEY_PATH

    called = False
    def fake_init(self, uri):
        nonlocal called
        called = True
        raise RuntimeError("JWKS should not be initialized when static key in use")
    monkeypatch.setattr(tv.PyJWKClient, "__init__", fake_init)

    # use an existing valid token; resolution should not trigger fake_init
    key = validator._resolve_signing_key(valid_token)
    assert not called, "JWKS client should not be constructed"


def test_empty_token_rejected(validator):
    with pytest.raises(TokenValidationError):
        validator.validate("")


def test_no_mfa_token(validator, token_no_mfa):
    claims = validator.validate(token_no_mfa)
    assert "mfa" not in claims.amr
    assert "pwd" in claims.amr


def test_invalid_signature_rejected(validator, invalid_signature_token):
    with pytest.raises(TokenValidationError, match="signature"):
        validator.validate(invalid_signature_token)


def test_er_physician_claims(validator, er_physician_token):
    claims = validator.validate(er_physician_token)
    assert claims.oid == "oid-dr-reddy-2233"
    assert "EMERGENCY_PHYSICIAN" in claims.roles
