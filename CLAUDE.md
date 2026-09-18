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
| Per-org Embedding Store | pgvector (Postgres extension) — ivfflat cosine index |
| Auth | PyJWT (HS256) |
| Logging | structlog (JSON structured output) |
| Metrics | prometheus-client (`GET /metrics`) |
| Outbound Webhooks | httpx (HMAC-SHA256 signed) |
| Migrations | Alembic (`alembic/versions/`) |
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
│   │   ├── pii_engine.py        # Step 3: Presidio PII masking (prompt) + rehydrate_pii()
│   │   ├── guardrails.py        # Step 4: keyword + prompt-injection + pgvector embedding check
│   │   └── response_scanner.py  # Step 5: Presidio PII scan on LLM response
│   ├── routers/
│   │   ├── proxy.py             # POST /v1/chat/completions (OpenAI-compatible, streaming + non-streaming)
│   │   ├── extension.py         # POST /v1/extension/* — browser-extension surface (see below)
│   │   ├── audit.py             # GET /audit/* endpoints
│   │   └── admin.py             # POST /admin/* endpoints
│   ├── models/
│   │   ├── request.py           # Pydantic input models
│   │   ├── response.py          # Pydantic output models
│   │   ├── audit.py             # SQLAlchemy ORM models (transactions, incidents, chain state)
│   │   ├── identity.py          # Department, Group, User, UserGroupMembership
│   │   ├── inventory.py         # AIProvider, AIModel, AIApp, BrowserInstallation
│   │   ├── embeddings.py        # PolicyEmbedding — per-org pgvector guardrail topics
│   │   ├── extension.py         # Pydantic contract for the browser-extension surface
│   │   └── policy.py            # Policy profile enums and config
│   ├── services/
│   │   ├── llm_router.py        # Provider routing + cost-based model selection
│   │   ├── audit_service.py     # Async audit log writer (hash-chains every write)
│   │   ├── audit_integrity.py   # Hash-chain canonicalization/append/verify
│   │   ├── identity_service.py  # X-VisorShield-User -> User row (get-or-create)
│   │   ├── inventory_service.py # Auto-discovers providers/models/apps/devices
│   │   ├── cost_calculator.py   # Real-time token cost computation
│   │   ├── report_service.py    # Monthly usage summary generator
│   │   ├── metrics.py           # Prometheus counters/histograms (GET /metrics)
│   │   └── webhook_service.py   # HMAC-signed guardrail-incident webhook delivery
│   ├── db/
│   │   ├── database.py          # SQLAlchemy async engine + session factory
│   │   └── migrations/
│   │       └── 001_initial.sql  # Legacy schema snapshot — alembic/versions/ is authoritative
│   └── policies/
│       ├── healthcare.py        # HIPAA/DPA template: recognizers + blocklist
│       ├── fintech.py           # PCI-DSS template: recognizers + blocklist
│       ├── govtech.py           # COA/DILG template: PH custom recognizers
│       └── legal_hr.py          # Bias/sensitivity template
├── alembic/
│   ├── env.py
│   └── versions/
│       ├── 0001_initial_schema.py
│       ├── 0002_pgvector_policy_embeddings.py
│       └── 0003_identity_inventory_audit_integrity.py
├── tests/
│   ├── test_proxy.py
│   ├── test_pii.py
│   ├── test_auth.py
│   └── test_guardrails.py
├── docker-compose.yml            # includes a one-shot `migrate` service (alembic upgrade head)
├── Dockerfile
├── requirements.txt
├── .env.example
├── docs/
│   └── Overview.md               # architecture overview for engineers new to the codebase
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
                        Placeholder → original map kept in request.state for
                        step-5 rehydration; original values never persisted.
      │
      ▼
[4] guardrails.py    → 3 layers, in order, first hit wins (451):
                          1. Keyword/regex blocklist
                          2. Prompt-injection heuristics ("ignore previous
                             instructions" family)
                          3. Embedding similarity — per-org pgvector topics
                             (ivfflat cosine search) if the org has any,
                             else the in-process default topic set
      │
      ▼
  LLM Provider       → Sanitized prompt sent to OpenAI or Anthropic.
                        Streaming (SSE) requests are buffered in full before
                        step 5 runs — never scanned/rehydrated chunk-by-chunk.
      │
      ▼
[5] response_scanner → Presidio masks any PII in the LLM response, then
                        (if PII_REHYDRATION_ENABLED) rehydrate_pii() restores
                        the caller's own masked values — order matters: mask
                        model-introduced PII first, then rehydrate the
                        caller's, never the reverse.
      │
      ▼
  Audit Logger       → Non-blocking asyncio.create_task() — never blocks response.
                        Guardrail hits also fire an async webhook (webhook_service.py)
                        when WEBHOOK_URL is configured — also non-blocking, best-effort.
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
| Missing X-VisorShield-User header | Block — required, see Identity Model. | 422 |
| Identity resolution (User upsert) DB error | **Fail-open.** Enrichment, not a security gate — proceeds with `user_id: None`. | n/a |
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

## Guardrails: Three-Layer Detection

`app/middleware/guardrails.py` runs three checks in order on every prompt.
The first hit blocks with 451 — later layers never run once an earlier one
fires:

1. **Keyword/regex blocklist** — synchronous, sub-millisecond, per policy profile.
2. **Prompt-injection heuristics** — `_check_prompt_injection()`, the "ignore
   previous instructions" family. Gated by `GUARDRAIL_PROMPT_INJECTION_ENABLED`.
3. **Embedding similarity** — cosine similarity against prohibited-topic
   vectors, threshold `EMBEDDING_SIMILARITY_THRESHOLD` (default `0.72`).

Layer 3 is **per-org first, default second**:
- Each org can have its own guardrail topics, stored as pgvector rows in
  `policy_embeddings` (`app/models/embeddings.py`), managed via
  `POST/GET/DELETE /admin/organizations/{org_id}/policy-embeddings`. These are
  searched with the `idx_policy_embeddings_ivfflat` cosine index
  (`IVFFLAT_PROBES` controls the recall/latency tradeoff).
- Whether an org has *any* custom topics is cached in-process for
  `EMBEDDING_CACHE_TTL_SECONDS` (a cheap `EXISTS` check) — the ANN search
  itself always hits Postgres live, so it stays correct as topics grow.
  `POST .../policy-embeddings` invalidates this presence cache immediately
  after writing (`invalidate_embedding_cache`).
- If an org has no custom rows for a policy profile (or the presence check
  itself errors), guardrails fall back to the in-process default topics for
  that profile, pre-computed once at startup by `warmup_embeddings()`.
- Never add a fourth layer or reorder these three without updating this file.

---

## PII Rehydration

`pii_engine.py`'s `rehydrate_pii()` restores the caller's own PII — the
values step 3 masked out of the prompt — back into the final response, so the
client sees real names instead of `[PERSON_1]` tokens. Gated by
`PII_REHYDRATION_ENABLED` (default `true`).

**Order matters, in `proxy.py`**: response_scanner (step 5) masks any PII the
*model* introduced first, then rehydration restores the *caller's* masked
values second. Never reverse this order — rehydrating first could hand the
response scanner values it would otherwise have flagged.

Streaming (SSE) responses are buffered in full before step 5 and rehydration
run — there is no per-chunk scanning. A response is never streamed to the
client until both steps have completed.

The one field that ever carries a real PII value in this system is
`ScanEntity.original` on the `/v1/extension/scan` response
(`app/models/extension.py`) — returned only to the extension that submitted
the prompt, never persisted, never logged, never part of an audit row.

---

## Webhook Alerts

`app/services/webhook_service.py` posts an HMAC-SHA256-signed JSON event to
`WEBHOOK_URL` whenever a guardrail incident is logged
(`audit_service.log_guardrail_incident()` calls `send_guardrail_alert()`).

- No-ops silently if `WEBHOOK_URL` is unset — this is an optional integration,
  not a gate.
- `WEBHOOK_MIN_SEVERITY` filters by `detection_layer` (`"all"` / `"keyword"` /
  `"prompt_injection"` / `"embedding"`).
- Signature goes in `X-VisorShield-Signature: sha256=<hmac>`, computed over
  the raw JSON body with `WEBHOOK_SECRET`. `config.py` refuses to start in
  production with `WEBHOOK_URL` set and `WEBHOOK_SECRET` unset.
- Delivery is fire-and-forget (`httpx.AsyncClient`, 10s timeout) — a slow or
  failing webhook endpoint must never add latency to or block the client
  response. Failures are logged (`webhook_delivery_failed`) and swallowed.

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
| `X-VisorShield-User` | Yes | Caller identity (SSO subject / email / employee ID) — see Identity Model below |
| `Content-Type` | Yes | `application/json` |

---

## Browser Extension Surface

`app/routers/extension.py` (`POST /v1/extension/*`) is a second entry point
for staff who paste prompts directly into chatgpt.com rather than calling the
API. VisorShield is **not** in the network path for that traffic — the
extension's content script captures the composer text, sends it here, gets
back a masked version, and types that into the page itself. Nothing is
forwarded to a provider from this surface.

It deliberately reuses pipeline steps 1–4 (`auth_middleware`,
`rate_limit_middleware`, the Presidio scan, `guardrails_middleware`) exactly
as the proxy does — same fail-closed rules, same 451/500/429 behavior. Step 5
is a separate call, `POST /v1/extension/response-scan`, invoked by the
extension only when the org's policy sets `audit_responses`, since only the
page can see the model's answer.

What's different from the proxy, and why:
- The masked prompt **and** the placeholder→original map are returned to the
  caller (`ScanEntity.original` in `app/models/extension.py`) instead of the
  map being used server-side for rehydration. That map is the
  re-identification key — never persisted, never logged — and the extension
  keeps it in `chrome.storage.session` only.
- No model call happens here, so there's no token usage or cost. Audit rows
  from this surface record zero tokens and an empty provider: a scan is a
  compliance event, not a spend event.

| Endpoint | Purpose |
|---|---|
| `POST /v1/extension/scan` | Steps 1–4 on a captured prompt → masked text + entity map, or 451 |
| `POST /v1/extension/response-scan` | Step 5 on the assistant's answer; types + placeholders only |
| `GET /v1/extension/policy` | Device policy, `fail_mode: closed` |
| `POST /v1/extension/events` | Metadata-only telemetry |
| `POST /v1/extension/heartbeat` | Device liveness → upserts `browser_installations` (see AI Inventory) |

---

## Identity Model

Tenancy used to stop at organizations + api_keys — every call under a shared
app/API key was indistinguishable, so "who is using which AI service" was
unanswerable. `X-VisorShield-User` closes that: `auth_middleware` resolves it
into a `User` row (`app/models/identity.py`), auto-provisioned on first sight
via `identity_service.get_or_create_user`.

- **`departments`** / **`groups`** — org-scoped groupings an admin curates via
  `/admin/departments` and `/admin/groups`. `groups` is cross-cutting
  (many-to-many via `user_group_memberships`); `department_id` is a single
  FK on `users`.
- **`users`** — one row per `(org_id, external_id)`, auto-provisioned, never
  hand-created. `external_id` is whatever the calling app already uses
  (SSO subject, email, employee ID) — VisorShield does not authenticate it,
  only tracks it. Curate via `PATCH /admin/users/{id}` (department, email,
  display name, active flag).
- **Resolution is fail-open, not fail-closed**: identity is an FinOps/policy
  enrichment, not a security gate — a DB hiccup here degrades to
  `user_id: None` (with `external_user_id` still recorded) rather than
  blocking the request. The org/API-key active check stays the actual gate
  and stays fail-closed (see Failure Modes).
- Every `Transaction` carries both `user_id` (nullable FK) and
  `external_user_id` (the raw header, always recorded) — `GET
  /audit/usage-by-user` is the "who is using AI" rollup.

---

## AI Inventory

There were no tables for providers, models, calling apps, or browser
installations — a governance proxy with nothing to show for what it's
actually governing. `app/models/inventory.py` holds four tables, all
**auto-discovered from observed traffic** (`app/services/inventory_service.py`),
not hand-entered:

| Table | Upserted from | Meaning |
|---|---|---|
| `ai_providers` / `ai_models` | Every completed transaction's `(provider, model_used)` | Catalog of what's actually been called. **Not** a pricing source — `cost_calculator.py` remains the only source of truth for pricing (see LLM Cost Routing Rules); `is_sanctioned` is a governance flag only. |
| `ai_apps` | Every transaction's `app_source` | Calling applications — the "shadow AI" surface. Toggle `is_sanctioned` via `PATCH /admin/inventory/apps/{id}`. |
| `browser_installations` | `POST /v1/extension/heartbeat` | One row per `device_id`, linked to `user_id` when resolved. |

List/sanction via `GET/PATCH /admin/inventory/{providers,models,apps,devices}`.

---

## Prometheus Metrics

`GET /metrics` (unauthenticated, like `/health` — scope access at the network
layer) exposes Prometheus exposition text via `app/services/metrics.py`. For a
governance product, "how many requests did we block, by policy, by org" is
the demo — the counters below are derived from data the pipeline already
produces (`request.state.pipeline_timing`, `GuardrailIncident` rows), not a
separate metrics pipeline:

| Metric | Type | Labels | Source |
|---|---|---|---|
| `visorshield_requests_total` | Counter | `org_id`, `industry_type`, `outcome` (`pass` / `blocked` / `upstream_error`) | `record_outcome()` — one call per request in `app/routers/proxy.py` |
| `visorshield_requests_blocked_total` | Counter | `org_id`, `industry_type`, `pipeline_step`, `reason` | `record_blocked()` in `_run_pipeline()` — catches every `HTTPException` from any of the 4 pre-LLM steps, not just guardrail 451s |
| `visorshield_guardrail_incidents_total` | Counter | `org_id`, `policy_profile`, `detection_layer`, `violation_category` | `record_guardrail_incident()` in `audit_service.log_guardrail_incident()` — mirrors `GuardrailIncident` rows, so this metric and `GET /audit/incidents` never disagree |
| `visorshield_pipeline_step_duration_ms` | Histogram | `pipeline_step` | `record_pipeline_timing()` — flushes `request.state.pipeline_timing` on every request (pass or block) |

`_run_pipeline()` in `proxy.py` is the single instrumentation point for
blocks — it wraps each of the 4 pipeline steps and records org/policy/step/
reason from the `HTTPException` it catches before re-raising it unchanged.
Add a new pipeline step to `_PIPELINE_STEPS` there, not a new try/except
elsewhere, so it's covered automatically.

---

## Audit Integrity

"Immutable audit" used to mean plain Postgres rows any admin (or anyone with
DB creds) could `UPDATE` with no trace. Two mechanisms now back that claim:

1. **Hash chain** (`app/services/audit_integrity.py`) — every `Transaction`
   commits to `record_hash = sha256(prev_hash || canonical_fields)`, chained
   per-org via the `audit_chain_state` anchor row (locked with `SELECT ...
   FOR UPDATE` on append, so concurrent fire-and-forget writes for the same
   org can't race and fork the chain). Editing a row after the fact breaks
   its own hash and every later link. `GET /audit/verify?org_id=...`
   recomputes the chain and reports the first broken link, if any.
2. **Append-only enforcement** — a `BEFORE UPDATE OR DELETE` trigger
   (`prevent_audit_mutation()`, migration 0003) rejects mutation of
   `transactions` and `guardrail_incidents` outright, at the DB engine level,
   regardless of which role issues the statement.

**Accepted boundary**: this does not survive a superuser dropping the trigger
and hand-editing prior links to match — the same boundary standard Postgres
audit-trigger extensions operate under. What it closes is routine admin
access or a compromised app credential quietly editing history.

`created_at` on `Transaction` is **application-generated**, not a DB
`server_default` — it must be committed to the hash before the row exists,
so the app always sets it explicitly (see `audit_service.log_transaction`).

**Export**: `GET /audit/export?format=csv|json` streams a bulk download
(capped at 50,000 rows per call; page with `date_from` beyond that) including
the hash-chain fields, so an exported file can be independently re-verified
offline.

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

# Guardrails (per-org pgvector layer — see Guardrails: Three-Layer Detection)
EMBEDDING_MODEL=paraphrase-MiniLM-L6-v2
PGVECTOR_DIMENSIONS=384
EMBEDDING_CACHE_TTL_SECONDS=300
IVFFLAT_PROBES=5
EMBEDDING_SIMILARITY_THRESHOLD=0.72
GUARDRAIL_PROMPT_INJECTION_ENABLED=true

# PII rehydration (see PII Rehydration)
PII_REHYDRATION_ENABLED=true

# Webhook alerts (see Webhook Alerts) — optional; unset WEBHOOK_URL disables entirely
WEBHOOK_URL=
WEBHOOK_SECRET=            # required if WEBHOOK_URL is set — enforced in production
WEBHOOK_MIN_SEVERITY=all   # all | keyword | prompt_injection | embedding
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

**Add a field to the audit record:**
1. Add the column to `Transaction` in `app/models/audit.py`
2. Add it to `canonical_transaction_fields(...)` in `app/services/audit_integrity.py` — it must be in the hash, or it's mutable without detection
3. Write an alembic migration (new revision, `down_revision` = current head) — never edit an already-applied migration
4. Thread it through `log_transaction(...)` call sites and `_tx_export_row` in `app/routers/audit.py`

**Set custom guardrail topics for an org (Layer 3 pgvector):**
1. `POST /admin/organizations/{org_id}/policy-embeddings` with `policy_profile` + `topics: [...]` — this embeds and upserts each topic into `policy_embeddings` and invalidates the presence cache immediately
2. `GET .../policy-embeddings` to list what's stored; `DELETE .../policy-embeddings/{policy_profile}` to clear a profile back to the default topic set
3. No migration needed — this is data, not schema

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
- **Never UPDATE or DELETE rows in `transactions` or `guardrail_incidents`.** The append-only trigger (`prevent_audit_mutation()`) rejects it at the DB level; if you need to fix bad data, insert a correction row, don't edit history.
- **Never add a field to `Transaction` without adding it to `canonical_transaction_fields(...)` in `audit_integrity.py`.** A column outside the hash is a column that can be silently edited without `/audit/verify` ever noticing.
- **Never make `X-VisorShield-User` optional or best-effort at the header level.** Identity *resolution* (the DB upsert) is allowed to fail open — see Failure Modes — but the header itself is required, same as `X-Industry-Type`.
- **Never rehydrate PII before the response scanner runs.** `rehydrate_pii()` must come *after* step 5 masks model-introduced PII — see PII Rehydration. Reversing the order can hand the scanner values it should have flagged.
- **Never scan or rehydrate a streaming response chunk-by-chunk.** Buffer the full SSE response first, then run step 5 and rehydration once — see Guardrails/PII Rehydration.
- **Never let webhook delivery block or fail the request.** `send_guardrail_alert()` is fire-and-forget with its own timeout; a slow or down webhook endpoint must never add latency to the client response.
- **Never reorder the three guardrail layers** (keyword → prompt-injection → embedding) or add a fourth without updating this file — see Guardrails: Three-Layer Detection.