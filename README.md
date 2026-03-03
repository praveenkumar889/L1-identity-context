# L1 — Identity & Context Resolution (v2.0)

**Apollo Hospitals Zero Trust NL-to-SQL Pipeline**
Layer 1: SecurityContext Assembly

---

## Architecture

```
   Azure AD JWT (RS256)
         │
         ▼
┌─────────────────────────────────────────┐
│  token_validation.py                     │
│  ├─ JWKS key resolution (mock RSA)       │
│  ├─ RS256 signature verification         │
│  ├─ Claims: iss, aud, exp, nbf, iat     │
│  └─ Extract: oid, name, roles, amr, jti │
└───────────────┬─────────────────────────┘
                │
         ┌──────┴──────┐
         ▼             ▼
┌────────────┐  ┌─────────────┐
│ redis_store │  │ user_       │
│ .py         │  │ enrichment  │
│ JTI check   │  │ .py         │
└──────┬─────┘  │ Mock HR/LDAP│
       │        └──────┬──────┘
       │               │
       │        ┌──────┴──────┐
       │        │ role_        │
       │        │ resolver.py  │
       │        │ Neo4j DAG    │
       │        │ Clearance    │
       │        │ MFA cap      │
       │        └──────┬──────┘
       │               │
       ▼               ▼
┌─────────────────────────────────────────┐
│  context_builder.py                      │
│  Assembles SecurityContext               │
└───────────────┬─────────────────────────┘
                │
         ┌──────┴──────┐
         ▼             ▼
┌────────────┐  ┌─────────────┐
│ signing.py │  │ redis_store │
│ HMAC-SHA256│  │ .py          │
│ Sign ctx   │  │ Store + TTL  │
└────────────┘  └─────────────┘
                │
                ▼
        { ctx_token, signature }
```

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/resolve-security-context` | JWT → SecurityContext (primary) |
| `POST` | `/break-glass` | Emergency access escalation |
| `POST` | `/revoke` | Context + JTI revocation |
| `GET`  | `/health` | Service health |
| `POST` | `/mock/token` | Generate test JWT (dev only) |

---

## Quick Start

```bash
docker compose up --build
# → http://localhost:8001/docs
```

### End-to-End Test

```bash
# 1. Generate a mock JWT
TOKEN=$(curl -s -X POST "http://localhost:8001/mock/token?oid=oid-dr-patel-4521&name=Dr.+Rajesh+Patel&email=dr.patel@apollohospitals.com&include_mfa=true" | jq -r '.token')

# 2. Resolve SecurityContext
curl -s -X POST http://localhost:8001/resolve-security-context \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3. Break-the-Glass (ER physician)
ER_TOKEN=$(curl -s -X POST "http://localhost:8001/mock/token?oid=oid-dr-reddy-2233&name=Dr.+Aditya+Reddy&roles=EMERGENCY_PHYSICIAN" | jq -r '.token')
CTX=$(curl -s -X POST http://localhost:8001/resolve-security-context \
  -H "Authorization: Bearer $ER_TOKEN" | jq -r '.ctx_token')
curl -s -X POST http://localhost:8001/break-glass \
  -H "Content-Type: application/json" \
  -d "{\"ctx_token\":\"$CTX\",\"reason\":\"Emergency cardiac arrest in ER bay 3, need full patient history immediately\"}" | jq .
```

---

## SecurityContext Structure

```json
{
  "ctx_id": "ctx_a1b2c3...",
  "version": "2.0",
  "identity": {
    "oid": "oid-dr-patel-4521",
    "name": "Dr. Rajesh Patel",
    "email": "dr.patel@apollohospitals.com",
    "jti": "uuid...",
    "mfa_verified": true,
    "auth_methods": ["pwd", "mfa"]
  },
  "org_context": {
    "employee_id": "DR-0001",
    "department": "Cardiology",
    "facility_ids": ["FAC-001"],
    "unit_ids": ["UNIT-1A-APJH", "UNIT-1B-APJH"],
    "provider_npi": "NPI-1234567890",
    "license_type": "MD",
    "employment_status": "ACTIVE"
  },
  "authorization": {
    "direct_roles": ["ATTENDING_PHYSICIAN"],
    "effective_roles": [
      "ATTENDING_PHYSICIAN", "CLINICIAN",
      "EMPLOYEE", "HEALTHCARE_PROVIDER",
      "HIPAA_COVERED_ENTITY", "SENIOR_CLINICIAN"
    ],
    "groups": ["clinical-cardiology"],
    "domain": "CLINICAL",
    "clearance_level": 4,
    "sensitivity_cap": 4,
    "bound_policies": ["CLIN-001", "HIPAA-001"]
  },
  "request_metadata": {
    "ip_address": "10.0.0.1",
    "user_agent": "...",
    "timestamp": "2026-02-28T...",
    "session_id": "ses_..."
  },
  "emergency": {
    "mode": "NONE"
  },
  "ttl_seconds": 900,
  "created_at": "...",
  "expires_at": "..."
}
```

---

## Role Inheritance Graph (Mock Neo4j)

```
ATTENDING_PHYSICIAN
  └─ SENIOR_CLINICIAN
       └─ CLINICIAN
            ├─ HEALTHCARE_PROVIDER
            │    └─ EMPLOYEE
            └─ HIPAA_COVERED_ENTITY

EMERGENCY_PHYSICIAN
  ├─ SENIOR_CLINICIAN (→ same tree above)
  └─ EMERGENCY_RESPONDER

PSYCHIATRIST
  ├─ SENIOR_CLINICIAN (→ same tree above)
  └─ RESTRICTED_DATA_HANDLER

BILLING_CLERK
  └─ FINANCE_STAFF
       └─ BUSINESS_STAFF
            └─ EMPLOYEE
       └─ HIPAA_COVERED_ENTITY

HR_DIRECTOR
  ├─ HR_STAFF → ADMIN_STAFF → EMPLOYEE
  └─ SENSITIVE_DATA_HANDLER
```

---

## Clearance Levels

| Level | Name | MFA Required | Example Data |
|-------|------|-------------|-------------|
| 5 | Restricted | Yes | Psychotherapy notes, substance abuse |
| 4 | Highly Confidential | Yes | Aadhaar, DOB, salary |
| 3 | Confidential | Recommended | Patient names, MRN, diagnosis |
| 2 | Internal | No | Staff schedules, equipment |
| 1 | Public | No | Facility names, department names |

**MFA Rule:** Without MFA, sensitivity_cap = clearance_level - 1 (floor: 1)

---

## File Structure

```
l1-identity-context/
├── app/
│   ├── main.py                      # FastAPI app + lifespan + logging
│   ├── config.py                    # Settings (env-driven, L1_ prefix)
│   ├── dependencies.py              # DI container for services
│   ├── models/
│   │   ├── enums.py                 # ClearanceLevel, Domain, EmergencyMode
│   │   ├── security_context.py      # SecurityContext (5 blocks)
│   │   └── requests.py              # API request/response models
│   ├── services/
│   │   ├── token_validation.py      # RS256 JWT + JWKS (mock RSA keypair)
│   │   ├── role_resolver.py         # Neo4j DAG inheritance + clearance + MFA cap
│   │   ├── user_enrichment.py       # Mock HR/LDAP (15 Apollo users)
│   │   ├── context_builder.py       # Orchestrator: JWT → SecurityContext
│   │   ├── signing.py               # HMAC-SHA256 deterministic signing
│   │   └── redis_store.py           # Redis sessions + JTI blacklist
│   ├── api/
│   │   └── routes.py                # All endpoints
│   └── data/
│       ├── users.json               # 15 test user profiles
│       └── roles.json               # 17 RBAC role definitions
├── tests/
│   ├── conftest.py                  # Fixtures (mock JWT gen for all personas)
│   ├── test_token_validation.py     # 8 tests: RS256, exp, aud, iss, amr
│   ├── test_role_resolver.py        # 17 tests: inheritance, clearance, MFA, domain
│   ├── test_signing.py              # 5 tests: determinism, verify, tamper
│   ├── test_context_builder.py      # 5 tests: full pipeline, revoke, JTI
│   └── test_api.py                  # 16 tests: endpoints, BTG, error cases
├── Dockerfile
├── docker-compose.yml               # App + Redis
├── requirements.txt
└── README.md
```

---

## Test Users (15 Apollo Personas)

| OID | Name | Role | Clearance | Domain |
|-----|------|------|-----------|--------|
| `oid-dr-patel-4521` | Dr. Rajesh Patel | ATTENDING_PHYSICIAN | 4 | Clinical |
| `oid-dr-sharma-1102` | Dr. Priya Sharma | CONSULTING_PHYSICIAN | 3 | Clinical |
| `oid-dr-reddy-2233` | Dr. Aditya Reddy | EMERGENCY_PHYSICIAN | 4 | Clinical |
| `oid-dr-iyer-3301` | Dr. Meera Iyer | PSYCHIATRIST | 5 | Clinical |
| `oid-nurse-kumar-2847` | Anita Kumar | REGISTERED_NURSE | 2 | Clinical |
| `oid-nurse-nair-3102` | Deepa Nair | ICU_NURSE | 3 | Clinical |
| `oid-nurse-singh-4455` | Rajesh Singh | HEAD_NURSE | 3 | Clinical |
| `oid-bill-maria-5521` | Maria Fernandes | BILLING_CLERK | 2 | Financial |
| `oid-bill-suresh-5530` | Suresh Gupta | REVENUE_CYCLE_ANALYST | 2 | Financial |
| `oid-rev-james-6601` | James Thomas | REVENUE_CYCLE_MANAGER | 2 | Financial |
| `oid-hr-priya-7701` | Priya Mehta | HR_MANAGER | 3 | Administrative |
| `oid-hr-dir-kapoor` | Rohit Kapoor | HR_DIRECTOR | 4 | Administrative |
| `oid-it-admin-7801` | Vikram Joshi | IT_ADMINISTRATOR | 2 | IT Operations |
| `oid-hipaa-officer` | Dr. Sunita Verma | HIPAA_PRIVACY_OFFICER | 5 | Compliance |
| `oid-researcher-das` | Dr. Anirban Das | CLINICAL_RESEARCHER | 2 | Research |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `L1_MOCK_IDP_ENABLED` | `true` | Use mock RSA keypair (false = real JWKS) |
| `L1_AZURE_CLIENT_ID` | `apollo-zt-pipeline` | Expected JWT audience |
| `L1_AZURE_ISSUER` | `https://login.microsoft...` | Expected JWT issuer |
| `L1_JWKS_URI` | Azure AD URL | JWKS endpoint for key fetch |
| `L1_HMAC_SECRET_KEY` | dev default | HMAC-SHA256 signing key |
| `L1_REDIS_URL` | `redis://localhost:6379/0` | Redis connection |
| `L1_CONTEXT_TTL_NORMAL` | `900` | SecurityContext TTL (15 min) |
| `L1_CONTEXT_TTL_EMERGENCY` | `14400` | BTG TTL (4 hours) |
| `L1_JWT_ALGORITHM` | `RS256` | JWT signature algorithm |
| `L1_JWT_LEEWAY_SECONDS` | `30` | Clock skew tolerance |
| `L1_BTG_MIN_REASON_LENGTH` | `20` | Min BTG justification chars |
| `L1_JWT_PRIVATE_KEY_PATH` | path | Optional PEM file containing RSA private key used for signing (overrides mock generation) |
| `L1_JWT_PUBLIC_KEY_PATH`  | path | Optional PEM file containing RSA public key used for verification; supersedes JWKS |
