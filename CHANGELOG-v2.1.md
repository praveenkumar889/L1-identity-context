# L1 Identity & Context v2.1 — Security Audit Remediation

**Date:** 2026-02-28
**Baseline:** v2.0 (88/100 audit score)
**Target:** All Critical + High + Medium issues from security audit

---

## Fixes Applied

### 🔴 CRITICAL

**C1 — Unknown users now DENIED by default**
- Removed `_DEFAULT_CONTEXT` fallback that granted ACTIVE status to unknown OIDs
- Added `UnknownUserError` exception — any OID not in directory → HTTP 403
- Added terminated test user (`oid-terminated-user-9999`) with `TERMINATED` status
- `ContextBuilder` catches both `UnknownUserError` and `InactiveEmployeeError` → 403

### 🟠 HIGH

**H1 — BTG/Revoke now use DI-injected TokenValidator**
- Removed inline `validator = TokenValidator()` from both route handlers
- Added `get_token_validator()` FastAPI dependency
- Both endpoints share the same JWKS cache and mock keypair singleton

**H2 — All Pydantic models frozen after construction**
- Added `model_config = ConfigDict(frozen=True)` to all 6 model classes:
  IdentityBlock, OrgContextBlock, AuthorizationBlock, RequestMetadataBlock,
  EmergencyBlock, SecurityContext
- BTG escalation already creates new objects (no mutation), fully compatible

**H3 — Rate limiting on all endpoints**
- New `app/services/rate_limiter.py` — in-memory sliding-window limiter
- `/resolve-security-context`: 30 req/min per IP
- `/break-glass`: 5 req/min per IP
- `/revoke`: 10 req/min per IP
- HTTP 429 with `Retry-After` header on limit exceeded
- Integrated via DI container (`get_rate_limiter()`)

### 🟡 MEDIUM

**M1 — CORS restricted to configured origins**
- Replaced `allow_origins=["*"]` with `CORS_ALLOWED_ORIGINS` from config
- Default: `localhost:3000`, `localhost:8001`, `*.apollohospitals.com`
- Methods restricted to GET/POST, headers to Authorization/Content-Type

**M2 — HMAC key startup validation**
- Default changed from hardcoded secret to empty string `""`
- `validate_for_startup()` called during lifespan:
  - Mock mode: auto-generates secure dev key via `secrets.token_hex(32)`
  - Production: raises `ValueError` if key empty or < 32 chars
- Old `"apollo-zt-hmac-secret-CHANGE-IN-PROD-2026"` removed

**M3 — Signature re-verification on Redis retrieval**
- `get_context()` now accepts optional `signature` + `signer` params
- When both provided, re-verifies HMAC before returning
- Logs `INTEGRITY VIOLATION` on mismatch, returns None

**M4 — BTG/Revoke check JTI blacklist**
- Both endpoints now call `store.is_jti_blacklisted()` after JWT validation
- Revoked JWTs can no longer call BTG or revoke → HTTP 401

**M5 — API-level JTI replay attack test**
- `TestJTIReplayAttack.test_jti_replay_blocked_after_revoke`:
  resolve → revoke → resolve again → assert 401

**M6 — Inactive/terminated employee tests**
- `TestInactiveEmployeeDenied.test_terminated_employee_rejected_403`
- `TestUnknownUserDenied.test_unknown_oid_rejected_403`
- Unit tests: `test_unknown_user_rejected`, `test_terminated_employee_rejected`
- New conftest fixtures: `terminated_employee_token`, `unknown_user_token`

**M7 — IP session binding**
- `ContextBuilder.validate_ip_binding()` static method
- BTG route validates caller IP matches original session IP
- Localhost/testclient IPs exempted (dev safety)
- Mismatch → `ContextBuildError(403)` with `IP BINDING VIOLATION` log

### BONUS

**BTG Ownership Enforcement Test**
- `TestBTGOwnershipEnforced.test_btg_wrong_owner_rejected`:
  ER physician creates context → billing clerk tries BTG → assert 403

---

## Metrics

| Metric | v2.0 | v2.1 |
|---|---|---|
| Total lines | ~3,000 | ~3,250 |
| Test count | 59 | 65 (+6) |
| Critical issues | 1 | 0 |
| High issues | 3 | 0 |
| Medium issues | 7 | 0 |
| New files | — | `rate_limiter.py` |
| Audit score | 88/100 | 97/100 (estimated) |

---

## Files Modified

- `app/services/user_enrichment.py` — C1: unknown user rejection + terminated test user
- `app/services/context_builder.py` — C1: catch UnknownUserError; M7: IP binding
- `app/models/security_context.py` — H2: frozen models
- `app/api/routes.py` — H1: DI validator; H3: rate limiting; M4: JTI blacklist; M7: IP check
- `app/dependencies.py` — H1: get_token_validator; H3: get_rate_limiter
- `app/services/rate_limiter.py` — H3: NEW FILE
- `app/services/redis_store.py` — M3: signature re-verification
- `app/config.py` — M1: CORS config; M2: HMAC validation
- `app/main.py` — M1: CORS origins; M2: startup validation call
- `tests/conftest.py` — M6: new fixtures
- `tests/test_api.py` — M5+M6: new test classes
- `tests/test_context_builder.py` — C1+M6: unit tests
