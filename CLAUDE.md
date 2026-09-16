# CLAUDE.md — VisorShield

This file is the source of truth for Claude Code when working on this codebase.
Read this before touching any file.

---

## What This Project Is

**VisorShield** is a Universal AI Governance Proxy — a FastAPI middleware service that sits between client applications and LLM providers (OpenAI, Anthropic). It enforces security, compliance, PII masking, cost control, and audit logging before any prompt reaches the LLM.

Think of it as a Zero-Trust API Gateway, but specifically designed for AI workloads across regulated industries (Healthcare, FinTech, GovTech, Legal/HR).

---

## Tech Stack

| Layer | Technology |
|---|---|
| API Framework | FastAPI 0.115+ |
| Runtime | Python 3.12 |
| Database | PostgreSQL 16 (async via asyncpg + SQLAlchemy) |
| Cache / Rate Limiting | Redis 7 (async via redis-py) |
| PII Detection | Microsoft Presidio (presidio-analyzer, presidio-anonymizer) |
| NLP Model | spaCy en_core_web_lg |
| Embeddings (Guardrails) | sentence-transformers paraphrase-MiniLM-L6-v2 |
| Auth | PyJWT (HS256) |
| Logging | structlog (JSON structured output) |
| Containerization | Docker + Docker Compose |
| Testing | pytest + pytest-asyncio + httpx + fakeredis |

---

## Project Structure

```
visorshield/
├── app/
│   ├── main.py                  # FastAPI app init, lifespan, router registration
│   ├── config.py                # Pydantic BaseSettings from .env
│   ├── dependencies.py          # Shared FastAPI dependency injectors
│   ├── middleware/
│   │   ├── auth.py              # Step 1: JWT validation + RBAC
│   │   ├── rate_limit.py        # Step 2: Redis spike arrest + monthly quota
│   │   ├── pii_engine.py        # Step 3: Presidio PII masking (prompt)
│   │   ├── guardrails.py        # Step 4: Keyword + embedding policy check
│   │   └── response_scanner.py  # Step 5: Presidio PII scan on LLM response
│   ├── routers/
│   │   ├── proxy.py             # POST /v1/chat/completions (OpenAI-compatible)
│   │   ├── audit.py             # GET /audit/* endpoints
│   │   └── admin.py             # POST /admin/* endpoints
│   ├── models/
│   │   ├── request.py           # Pydantic input models
│   │   ├── response.py          # Pydantic output models
│   │   ├── audit.py             # SQLAlchemy ORM models
│   │   └── policy.py            # Policy profile enums and config
│   ├── services/
│   │   ├── llm_router.py        # Provider routing + cost-based model selection
│   │   ├── audit_service.py     # Async audit log writer
│   │   ├── cost_calculator.py   # Real-time token cost computation
│   │   └── report_service.py    # Monthly usage summary generator
│   ├── db/
│   │   ├── database.py          # SQLAlchemy async engine + session factory
│   │   └── migrations/
│   │       └── 001_initial.sql  # Full schema (run once on fresh DB)
│   └── policies/
│       ├── healthcare.py        # HIPAA/DPA template: recognizers + blocklist
│       ├── fintech.py           # PCI-DSS template: recognizers + blocklist
│       ├── govtech.py           # COA/DILG template: PH custom recognizers
│       └── legal_hr.py          # Bias/sensitivity template
├── tests/
│   ├── test_proxy.py
│   ├── test_pii.py
│   ├── test_auth.py
│   └── test_guardrails.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
├── .env.example
├── CLAUDE.md                    # ← You are here
└── README.md
```

---

## Interceptor Pipeline Order

**This order is non-negotiable. Never reorder these steps.**

```
Incoming Request
      │
      ▼
[1] auth.py          → Validate JWT. Cross-check X-Industry-Type header against
                        the token's industry_type claim (mismatch = 403).
                        Load live org/key state from the DB — allowed_models,
                        requests_per_second, monthly_token_budget override the
                        token's own copies. Extract org_id, role.
      │
      ▼
[2] rate_limit.py    → Redis spike arrest + monthly token quota check.
      │
      ▼
[3] pii_engine.py    → Presidio masks PII in prompt using industry template.
      │
      ▼
[4] guardrails.py    → Keyword blocklist + embedding similarity policy check.
      │
      ▼
  LLM Provider       → Sanitized prompt sent to OpenAI or Anthropic.
      │
      ▼
[5] response_scanner → Presidio masks any PII in the LLM response.
      │
      ▼
  Audit Logger       → Non-blocking asyncio.create_task() — never blocks response.
      │
      ▼
Client Response
```

---

## Failure Modes (Critical — Do Not Change)

| Step | Failure Behavior | HTTP Code |
|---|---|---|
| Auth failure | Block. Return error. | 401 / 403 |
| X-Industry-Type / JWT industry_type mismatch | Block. Never silently pick either value. | 403 |
| Auth DB unreachable (org/key active check) | **Fail-closed. Block request.** (see `AUTH_FAIL_OPEN_ON_DB_ERROR`) | 503 |
| Rate limit exceeded | Block. Return reset_date. | 429 |
| PII scan exception | **Fail-closed. Block request.** | 500 |
| Guardrails hit | Block. Log incident. Never forward to LLM. | 451 |
| Response PII detected | Mask response. Log. Never return raw PII. | 200 (masked) |
| LLM provider 5xx | Retry once → fallback provider → 502 | 502 |

**The PII engine must always fail-closed.** If Presidio throws any exception, the request is blocked. Never fail-open on PII.

**The auth DB check must default to fail-closed too.** If the org/API-key active check in `auth.py` can't reach Postgres, block the request (503) rather than let a possibly-revoked key or deactivated org through as "unknown". `AUTH_FAIL_OPEN_ON_DB_ERROR` exists to relax this outside production only — `config.py` refuses to start in production with it set.

---

## Industry Policy Profiles

Set via `X-Industry-Type` request header. Valid values:

| Header Value | Profile | Key Entities |
|---|---|---|
| `healthcare` | HIPAA / DPA | PERSON, PHONE_NUMBER, EMAIL_ADDRESS, MEDICAL_LICENSE, US_SSN, DATE_TIME |
| `fintech` | PCI-DSS / SEC | CREDIT_CARD, IBAN_CODE, SWIFT_BIC, PHONE_NUMBER, EMAIL_ADDRESS, US_BANK_NUMBER |
| `govtech` | COA / DILG | PH_TIN, PH_SSS, PH_PHILSYS (custom), PERSON, PHONE_NUMBER, EMAIL_ADDRESS |
| `legal_hr` | Bias / Sensitivity | PERSON, EMAIL_ADDRESS, PHONE_NUMBER, AGE, NRP |

### Philippine Custom Recognizers (govtech profile)

These are custom Presidio recognizers — regex-based:

- **PH_TIN** — format: `XXX-XXX-XXX-XXX` (12 digits, dashes)
- **PH_SSS** — format: `XX-XXXXXXX-X`
- **PH_PHILSYS** — 16 consecutive digits

These live in `app/policies/govtech.py`. If BIR or PSA changes formats, update the regex there only.

---

## Redis Key Naming Convention

All Redis keys must be namespaced. Never use bare keys.

```
visorshield:{org_id}:{api_key_hash}:rps          # requests per second counter (sliding 1s window)
visorshield:{org_id}:{api_key_hash}:monthly_tokens  # monthly token accumulator
visorshield:{org_id}:budget_alert_sent           # flag: monthly alert already sent
```

TTL rules:
- `rps` key: ~5 seconds (just long enough to cover clock skew on the 1s window)
- `monthly_tokens` key: expires on 1st of next month (compute dynamically)

The rate limit is a literal **requests-per-second** value — same unit as the
`requests_per_second` JWT claim below and the `requests_per_second_limit`
column on `organizations`. Do not reintroduce a "per minute" reading of this
number anywhere (claim name, Redis key, or comparison window) — that was a
real bug (three different contracts for one number) and caused the spike
arrest to be ~60x too permissive.

---

## JWT Claims Schema

Every valid JWT must contain these claims:

```json
{
  "sub": "api_key_id",
  "org_id": "uuid",
  "app_source": "HR-Portal",
  "role": "app | compliance_officer | admin",
  "allowed_models": ["gpt-4o-mini", "gpt-4o"],
  "requests_per_second": 10,
  "monthly_token_budget": 1000000,
  "industry_type": "govtech",
  "exp": 1234567890
}
```

- `role: app` — can call `/v1/chat/completions` only
- `role: compliance_officer` — can call `/audit/*` endpoints
- `role: admin` — can call all endpoints including `/admin/*`
- `industry_type` is **required** and `auth.py` rejects the request (403) if the
  `X-Industry-Type` header doesn't match it exactly. The header alone is never
  trusted for policy selection — a caller sending a different header than the
  claim would otherwise get a different (weaker) entity list / blocklist than
  their org was issued.
- `allowed_models`, `requests_per_second`, and `monthly_token_budget` in the
  token are **defaults only**. `auth.py` overwrites them at request time with
  the live values from the `organizations` row (via `/admin/organizations`),
  so an admin-changed budget or model list takes effect immediately without
  waiting for tokens to expire and be reminted.

---

## LLM Cost Routing Rules

The `llm_router.py` service auto-routes to cheaper models when appropriate.

**Route to cheap model when ALL of these are true:**
- Input token count < 500
- Complexity score < 0.4 (keyword heuristic: no words like "analyze", "compare", "summarize", "generate", "explain in detail")
- Org's `allowed_models` includes the cheaper model

**Pricing table (hardcoded in `cost_calculator.py`):**

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|---|---|---|
| gpt-4o | $5.00 | $15.00 |
| gpt-4o-mini | $0.15 | $0.60 |
| claude-sonnet-4-5 | $3.00 | $15.00 |
| claude-haiku-4-5 | $0.25 | $1.25 |

Update this table when provider pricing changes. This is the single source of truth for cost tracking.

---

## Audit Logging Rules

- **Prompt hash**: SHA-256 of the **original** (pre-masked) prompt. Computed before masking. Stored as hex string. Never store raw prompt text.
- **Audit writes are non-blocking**: Always use `asyncio.create_task(audit_service.log(...))`. Never await audit writes in the request path.
- **Response PII** is logged separately as `response_pii_detected` JSON array.
- **`pipeline_timing`**: Every middleware step appends its execution time (ms) to `request.state.pipeline_timing` dict. This is summed into `latency_ms` in the audit record.

---

## Required Headers on Every Request

| Header | Required | Description |
|---|---|---|
| `Authorization` | Yes | `Bearer <jwt>` |
| `X-Industry-Type` | Yes | `healthcare / fintech / govtech / legal_hr` |
| `X-Org-ID` | Yes | Organization UUID |
| `Content-Type` | Yes | `application/json` |

---

## Required Response Headers

| Header | Description |
|---|---|
| `X-VisorShield-Request-ID` | UUID generated at pipeline entry. Present on every response. |
| `X-VisorShield-PII-Masked` | `true / false` — whether PII was detected and masked |
| `X-VisorShield-Model-Used` | Actual model routed to (may differ from requested) |

---

## Structured Logging Format

Use `structlog`. Every log entry must include:

```json
{
  "timestamp": "2025-01-01T00:00:00Z",
  "level": "info",
  "event": "pii_masked",
  "org_id": "uuid",
  "request_id": "uuid",
  "pipeline_step": "pii_engine",
  "pii_types": ["PERSON", "PH_SSS"],
  "industry_type": "govtech"
}
```

Never log: raw prompt text, PII values, JWT secrets, API keys.

---

## Environment Variables

See `.env.example` for the full list. Critical ones:

```
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/visorshield
REDIS_URL=redis://localhost:6379/0
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
JWT_SECRET=<min 32 char random string>
JWT_ALGORITHM=HS256
DEFAULT_PROVIDER=openai
FALLBACK_PROVIDER=anthropic
ENVIRONMENT=development
AUTH_FAIL_OPEN_ON_DB_ERROR=false  # never true in production — see Failure Modes
```

---

## Testing Conventions

- All tests use `pytest-asyncio` with `asyncio_mode = "auto"` in `pytest.ini`
- Mock LLM provider calls using `pytest-mock` — never make real API calls in tests
- Use `fakeredis.aioredis.FakeRedis` for Redis mocking
- Use `httpx.AsyncClient` with FastAPI's `app` directly (no real server needed)
- Test files map 1:1 to the component they test

**Run tests:**
```bash
pytest tests/ -v --tb=short
```

---

## Common Tasks

**Add a new industry policy profile:**
1. Create `app/policies/<industry>.py` with recognizer list and blocklist
2. Add the new value to the `IndustryType` enum in `app/models/policy.py`
3. Register it in `app/middleware/pii_engine.py` template loader
4. Register it in `app/middleware/guardrails.py` policy loader
5. Add a test case in `tests/test_pii.py`

**Update LLM pricing:**
- Edit the pricing table in `app/services/cost_calculator.py` only. Nowhere else.

**Add a new LLM provider:**
1. Add provider client in `app/services/llm_router.py`
2. Add pricing entries in `app/services/cost_calculator.py`
3. Add provider name to the `Provider` enum in `app/models/policy.py`

---

## What NOT To Do

- **Never store raw prompt text** anywhere — DB, logs, or cache. Hash only.
- **Never fail-open on PII scanning.** If Presidio errors, block the request.
- **Never bypass the interceptor pipeline** by calling the LLM directly from a router.
- **Never await audit log writes** in the request path — always `create_task`.
- **Never hardcode org_id or api keys** in test files — use fixtures.
- **Never reorder the interceptor pipeline** steps without updating this file.
- **Never log PII values** — log entity types only (e.g., `"PERSON"` not `"Juan dela Cruz"`).
- **Never select a policy profile from the raw `X-Industry-Type` header.** Only use it after `auth.py` has confirmed it matches the JWT's `industry_type` claim; downstream steps (`pii_engine.py`, `guardrails.py`) read `request.state.jwt_claims["industry_type"]`, not the header.
- **Never fall back to JWT-only org limits when the DB fetch in `auth.py` succeeds.** The DB row is authoritative for `allowed_models`, `requests_per_second`, and `monthly_token_budget`; the JWT values are only a fallback for when the DB check itself is skipped or explicitly fails open.