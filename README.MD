# VisorShield

**Universal AI Governance Proxy for Regulated Industries**

VisorShield is a Zero-Trust middleware layer that sits between your applications and LLM providers (OpenAI, Anthropic). It enforces PII masking, compliance guardrails, cost control, and audit logging — so your teams can use AI freely without risking data privacy violations or regulatory exposure.

> Drop-in compatible with the OpenAI API. Change one line of code. Everything else stays the same.

---

## The Problem It Solves

When employees use AI tools, they unknowingly paste sensitive data into prompts:

- A nurse types a patient's full name, birthdate, and diagnosis into an AI chatbot
- A finance agent pastes a customer's credit card number to ask for a summary
- An LGU staff member includes a citizen's PhilSys ID in a query

Without a governance layer, **that data goes directly to a foreign cloud provider's servers**, unmasked and unlogged. That's a DPA violation, a PCI-DSS breach, and a COA audit nightmare waiting to happen.

**VisorShield intercepts every prompt, masks the sensitive data, enforces policy, and logs everything** — before a single token reaches OpenAI or Anthropic.

---

See [`docs/Overview.md`](docs/Overview.md) for a deeper architecture walkthrough than this README covers.

## How It Works

```
Your App  →  POST /v1/chat/completions  →  VisorShield  →  OpenAI / Anthropic
                                               │
                                    ┌──────────▼──────────┐
                                    │  1. Auth & RBAC      │
                                    │  2. Rate Limiting    │
                                    │  3. PII Masking      │
                                    │  4. Guardrails (3 layers)│
                                    │  5. Response Scan +  │
                                    │     PII Rehydration  │
                                    │  6. Audit Logging    │
                                    └─────────────────────┘
```

Requests are also accepted through a **browser extension surface**
(`POST /v1/extension/*`) for staff who paste prompts directly into
chatgpt.com instead of calling an API — see [Browser Extension Support](#browser-extension-support).

Clients switch from OpenAI to VisorShield by changing **one line**:

```python
# Before
client = OpenAI(base_url="https://api.openai.com/v1")

# After
client = OpenAI(base_url="https://your-visorshield-instance.com/v1")
```

---

## Features

### PII Masking, Rehydration & Response Scanning
Detects and replaces sensitive entities before the prompt leaves your infrastructure, using Microsoft Presidio. The LLM response is scanned too — because models can reconstruct or echo back PII from context.

If **rehydration** is enabled (`PII_REHYDRATION_ENABLED`, default on), the caller's *own* masked values are restored into the final response after the response scan runs — the client sees real names, not `[PERSON_1]` tokens, while the LLM itself never saw them. Streaming (SSE) responses are buffered in full before scanning/rehydration; there is no partial-chunk PII exposure.

### Industry Policy Profiles
Set via a single request header, cross-checked against the caller's JWT so the header alone can never select a weaker policy. Four built-in templates:

| Profile | Header Value | Compliance Target |
|---|---|---|
| Healthcare | `healthcare` | HIPAA / Philippine DPA |
| FinTech | `fintech` | PCI-DSS / SEC |
| Government | `govtech` | COA / DILG — includes PhilSys, TIN, SSS |
| Legal / HR | `legal_hr` | Bias & sensitivity filtering |

### Compliance Guardrails
Three-layer policy enforcement, first hit blocks with `451`:
- **Layer 1** — Fast keyword/regex blocklist (sub-millisecond)
- **Layer 2** — Prompt-injection heuristics ("ignore previous instructions" family)
- **Layer 3** — Embedding similarity against prohibited-topic vectors, searched per-org first: each org can define its own guardrail topics (stored in Postgres via `pgvector`, queried with an ivfflat cosine index), falling back to the built-in default topics for orgs that haven't customized theirs

Example: An LGU chatbot won't give medical advice. A finance bot won't give legal advice. Violations are blocked and logged as incidents — and optionally pushed to an HMAC-signed webhook in real time (see below).

### Cost Control & Smart Routing
- Per-org monthly token budgets enforced via Redis
- Spike arrest: configurable requests-per-second limit per API key
- Automatic model downgrade for simple prompts (saves cost without degrading output quality)
- Real-time cost tracking per request, per department, per month

### Identity & Departments
`X-VisorShield-User` (required on every request) is resolved into a `User` row, auto-provisioned on first sight — so usage under a shared app/API key is no longer anonymous. Admins curate `departments` and cross-cutting `groups`, and can query "who is using AI, how much" via `GET /audit/usage-by-user`. Identity resolution itself fails **open** (a DB hiccup degrades to `user_id: None`, never blocks the request) — it's an enrichment layer, not a security gate.

### AI Inventory (Shadow AI Discovery)
Providers, models, calling applications, and browser-extension installations are all **auto-discovered from observed traffic** — nothing to hand-enter. Toggle governance flags (`is_sanctioned`) per model or app via `/admin/inventory/*` once you see what's actually being called.

### Audit Ledger with Tamper-Evident Hash Chain
Every request is logged with:
- Prompt hash (SHA-256 — raw prompts are never stored)
- PII entity types detected (not the values)
- Model requested vs. model used
- Token counts, cost in USD
- Compliance pass/fail status
- Latency per pipeline step

Every `Transaction` and `GuardrailIncident` row also commits to a per-org SHA-256 **hash chain** (`record_hash = sha256(prev_hash || fields)`), and a database trigger rejects any `UPDATE`/`DELETE` on those tables outright — at the engine level, regardless of which role issues the statement. `GET /audit/verify` recomputes the chain and reports the first broken link, if any. `GET /audit/export` streams a bulk CSV/JSON download for offline re-verification.

Built for SOC2 audits, COA transparency requirements, and DPO reviews.

### Prometheus Metrics
`GET /metrics` exposes request/block/incident counters and per-pipeline-step latency histograms, labeled by org, industry profile, pipeline step, and reason — so "how many requests did we block, by policy, by org" is a dashboard query, not a log grep.

### Webhook Alerts
Guardrail incidents can be pushed in real time to any HTTPS endpoint (`WEBHOOK_URL`), signed with HMAC-SHA256 (`X-VisorShield-Signature`) and filterable by detection layer (`WEBHOOK_MIN_SEVERITY`). Delivery is fire-and-forget and never adds latency to — or blocks — the client response.

### Browser Extension Support
For staff who paste prompts directly into chatgpt.com rather than calling an API, `POST /v1/extension/*` runs the same auth/rate-limit/PII/guardrail pipeline and hands back a masked prompt + entity map for the extension to type into the page itself. VisorShield is never in the network path for that traffic — see [Browser Extension Endpoints](#browser-extension-endpoints).

---

## Quick Start

### Prerequisites

- Docker + Docker Compose
- Python 3.12 (for local dev — **not 3.13+**; spaCy/thinc/blis and asyncpg have no 3.13 wheels, so `pip install` falls back to source builds that fail)
- OpenAI and/or Anthropic API keys

### 1. Clone and configure

```bash
git clone https://github.com/your-org/visorshield.git
cd visorshield
cp .env.example .env
```

Edit `.env` with your API keys and a strong JWT secret (minimum 32 characters).

### 2. Start the stack

```bash
docker-compose up -d
```

This starts:
- **VisorShield API** on `http://localhost:8000`
- **PostgreSQL 16** on port 5432
- **Redis 7** on port 6379

### 3. Run database migrations

`docker-compose up` already runs a one-shot `migrate` service (`alembic upgrade head`) before the API container starts, so this step is normally automatic. To run it manually (e.g. after pulling new migrations):

```bash
docker exec -it visorshield-api alembic upgrade head
```

`app/db/migrations/001_initial.sql` is a legacy schema snapshot kept for reference only — `alembic/versions/` is the authoritative migration history. Migration `0002` requires the Postgres `pgvector` extension (used for per-org guardrail topics); the official `pgvector/pgvector` Postgres image used in `docker-compose.yml` has it preinstalled.

### 4. Download NLP models (first run only)

```bash
docker exec visorshield-api python -m spacy download en_core_web_lg
```

Note: This downloads ~700MB. Only needed once.

### 5. Verify the service

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "presidio": "loaded",
  "version": "1.0.0"
}
```

---

## Generating a JWT for Testing

Use the admin endpoint to create an org and API key, then generate a test JWT with this payload:

```json
{
  "sub": "api_key_id_here",
  "org_id": "your-org-uuid",
  "app_source": "LGU-Chatbot",
  "role": "app",
  "allowed_models": ["gpt-4o-mini", "gpt-4o"],
  "requests_per_second": 10,
  "monthly_token_budget": 1000000,
  "industry_type": "govtech",
  "exp": 9999999999
}
```

Sign with your `JWT_SECRET` using HS256.

---

## Making Your First Request

Every request needs five headers — `Authorization`, `X-Industry-Type`, `X-Org-ID`, `X-VisorShield-User`, and `Content-Type`. `X-VisorShield-User` is your own caller identity (SSO subject, email, or employee ID); VisorShield auto-provisions a `User` row for it on first sight — it doesn't authenticate it, only tracks it for usage-by-user reporting.

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer <your_jwt>" \
  -H "X-Industry-Type: govtech" \
  -H "X-Org-ID: your-org-uuid" \
  -H "X-VisorShield-User: juan.delacruz@lgu.gov.ph" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {
        "role": "user",
        "content": "Summarize the case of Juan dela Cruz, PhilSys 1234567890123456, TIN 123-456-789-000"
      }
    ]
  }'
```

What VisorShield does with that prompt before sending it to OpenAI:

```
"Summarize the case of [PERSON_1], PhilSys [PH_PHILSYS_1], TIN [PH_TIN_1]"
```

Response headers you'll receive:

```
X-VisorShield-Request-ID: 550e8400-e29b-41d4-a716-446655440000
X-VisorShield-PII-Masked: true
X-VisorShield-Model-Used: gpt-4o-mini
```

---

## API Reference

### Proxy

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat endpoint (streaming and non-streaming) |
| `GET` | `/health` | Service health check |
| `GET` | `/metrics` | Prometheus exposition (unauthenticated — scope access at the network layer) |

### Browser Extension Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/extension/scan` | Steps 1–4 on a captured prompt → masked text + entity map, or `451` |
| `POST` | `/v1/extension/response-scan` | Step 5 on the assistant's answer; types + placeholders only |
| `GET` | `/v1/extension/policy` | Device policy, `fail_mode: closed` |
| `POST` | `/v1/extension/events` | Metadata-only telemetry |
| `POST` | `/v1/extension/heartbeat` | Device liveness — upserts a `browser_installations` row |

### Audit (requires `compliance_officer` or `admin` role)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/audit/transactions` | Paginated transaction log |
| `GET` | `/audit/transactions/{id}` | Single transaction detail |
| `GET` | `/audit/incidents` | Guardrail violation incidents |
| `GET` | `/audit/summary` | Aggregate stats (tokens, cost, PII events, compliance rate) |
| `GET` | `/audit/usage-by-user` | Usage rollup by `X-VisorShield-User` identity |
| `GET` | `/audit/export` | Bulk CSV/JSON export (up to 50,000 rows/call), includes hash-chain fields |
| `GET` | `/audit/verify` | Recomputes the per-org hash chain; reports the first broken link, if any |

### Admin (requires `admin` role)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/admin/organizations` | Create a new organization |
| `PATCH` | `/admin/organizations/{id}` | Update org limits (`allowed_models`, `requests_per_second`, `monthly_token_budget`, ...) |
| `DELETE` | `/admin/organizations/{id}` | Deactivate an organization |
| `POST` | `/admin/api-keys` | Generate API key for an org |
| `DELETE` | `/admin/api-keys/{id}` | Revoke an API key |
| `GET` | `/admin/organizations/{id}/usage` | Current month usage vs. budget |
| `POST` | `/admin/organizations/{id}/policy-embeddings` | Upsert per-org custom guardrail topics (pgvector, Layer 3) |
| `GET` | `/admin/organizations/{id}/policy-embeddings` | List an org's custom guardrail topics |
| `DELETE` | `/admin/organizations/{id}/policy-embeddings/{profile}` | Clear an org's custom topics for a profile (reverts to defaults) |
| `POST` | `/admin/reports/monthly` | Generate monthly usage summary |
| `POST` / `GET` | `/admin/departments` | Create / list org departments |
| `POST` / `GET` | `/admin/groups` | Create / list org groups |
| `POST` | `/admin/groups/{id}/members/{user_id}` | Add a user to a group |
| `GET` | `/admin/users` | List org users (auto-provisioned from `X-VisorShield-User`) |
| `PATCH` | `/admin/users/{id}` | Curate a user (department, email, display name, active flag) |
| `GET` / `PATCH` | `/admin/inventory/providers` | List / sanction auto-discovered LLM providers |
| `GET` / `PATCH` | `/admin/inventory/models` | List / sanction auto-discovered models |
| `GET` / `PATCH` | `/admin/inventory/apps` | List / sanction calling applications (shadow AI surface) |
| `GET` | `/admin/inventory/devices` | List browser-extension installations |

---

## Running Tests

```bash
# Create a virtualenv on Python 3.12 (not 3.13+ — see Prerequisites)
python3.12 -m venv .venv
source .venv/bin/activate

# Install dev dependencies
pip install -r requirements.txt

# Download the spaCy model Presidio needs (~400MB, first run only).
# test_pii.py builds a real AnalyzerEngine, so tests fail without it.
python -m spacy download en_core_web_lg

# Run all tests
pytest tests/ -v --tb=short

# Run a specific test file
pytest tests/test_pii.py -v
```

Test coverage targets:
- `test_proxy.py` — Happy path, model access control, quota enforcement
- `test_pii.py` — All four industry templates, fail-closed behavior
- `test_auth.py` — Invalid JWT, expired token, insufficient role
- `test_guardrails.py` — Keyword hit, embedding similarity hit, HTTP 451 response

---

## Configuration Reference

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string (asyncpg) |
| `REDIS_URL` | Yes | Redis connection string |
| `OPENAI_API_KEY` | Yes* | OpenAI API key |
| `ANTHROPIC_API_KEY` | Yes* | Anthropic API key |
| `JWT_SECRET` | Yes | HS256 signing secret (min 32 chars) |
| `JWT_ALGORITHM` | No | Default: `HS256` |
| `JWT_EXPIRY_HOURS` | No | Default: `24` |
| `DEFAULT_PROVIDER` | No | Default: `openai` |
| `FALLBACK_PROVIDER` | No | Default: `anthropic` |
| `EMBEDDING_MODEL` | No | Default: `paraphrase-MiniLM-L6-v2` |
| `PGVECTOR_DIMENSIONS` | No | Default: `384` — must match `EMBEDDING_MODEL`'s output dimension |
| `EMBEDDING_CACHE_TTL_SECONDS` | No | Default: `300` — TTL for the per-org "has custom topics" presence cache |
| `IVFFLAT_PROBES` | No | Default: `5` — recall/latency tradeoff for the pgvector ANN search |
| `EMBEDDING_SIMILARITY_THRESHOLD` | No | Default: `0.72` — cosine similarity cutoff for Guardrail Layer 3 |
| `GUARDRAIL_PROMPT_INJECTION_ENABLED` | No | Default: `true` — Guardrail Layer 2 |
| `PII_REHYDRATION_ENABLED` | No | Default: `true` — restore caller's own PII in the final response |
| `WEBHOOK_URL` | No | HTTPS endpoint for guardrail-incident alerts; unset disables webhooks entirely |
| `WEBHOOK_SECRET` | No* | HMAC-SHA256 signing secret — required if `WEBHOOK_URL` is set (enforced in production) |
| `WEBHOOK_MIN_SEVERITY` | No | Default: `all` — filter by detection layer (`all` / `keyword` / `prompt_injection` / `embedding`) |
| `AUTH_FAIL_OPEN_ON_DB_ERROR` | No | Default: `false` — never `true` in production; see Security Notes |
| `LOG_LEVEL` | No | Default: `INFO` |
| `ENVIRONMENT` | No | `development / staging / production` |

*At least one provider key is required. `WEBHOOK_SECRET` is required only when `WEBHOOK_URL` is set.

---

## Deployment

### Docker Compose (Recommended for on-premise)

The included `docker-compose.yml` is production-ready for single-server deployments. Suitable for LGU servers, hospital networks, or any on-premise requirement.

```bash
docker-compose -f docker-compose.yml up -d
```

### Azure (Cloud)

Recommended setup for cloud deployments:
- **VisorShield API** → Azure Container Apps (or Azure App Service)
- **PostgreSQL** → Azure Database for PostgreSQL Flexible Server (Philippines region: Southeast Asia)
- **Redis** → Azure Cache for Redis
- **Secrets** → Azure Key Vault

Data residency: Deploy to **Azure Southeast Asia (Singapore)** for lowest latency from the Philippines, or **Azure East Asia** depending on your data residency requirements.

### Environment-specific notes

For Philippine government deployments, consult your agency's DICT cloud procurement guidelines before choosing a hosting region. VisorShield's self-hosted Docker option satisfies on-premise requirements without cloud dependency.

---

## Adding a New Industry Profile

1. Create `app/policies/<industry>.py` with recognizer definitions and topic blocklist
2. Add the new value to `IndustryType` enum in `app/models/policy.py`
3. Register recognizers in `app/middleware/pii_engine.py`
4. Register topic blocklist in `app/middleware/guardrails.py`
5. Add test cases in `tests/test_pii.py`

See `app/policies/govtech.py` as the reference implementation (includes custom Philippine entity recognizers).

---

## Known Limitations & Roadmap

| Item | Status |
|---|---|
| PDF report generation for monthly audits | Planned |
| Per-org guardrail topics via pgvector (Layer 3) | Shipped |
| Webhook alerts on guardrail incidents | Shipped — quota-threshold alerts still planned |
| PII rehydration (re-inject caller's masked values into the response) | Shipped |
| Streaming (SSE) response support | Shipped — buffered before PII scan/rehydration, not scanned chunk-by-chunk |
| AI inventory auto-discovery (providers/models/apps/devices) | Shipped |
| Audit hash-chain integrity + append-only enforcement | Shipped |
| Multi-region data residency config | Planned |
| Web dashboard (Next.js) | Separate repo |
| Support for Azure OpenAI endpoint | Planned |

---

## Security Notes

- Raw prompt text is **never stored** anywhere. Only SHA-256 hashes.
- PII values are **never logged**. Only entity type labels (e.g., `"PERSON"`, `"PH_SSS"`).
- The PII engine **fails closed** — any Presidio exception blocks the request. It will never fail silently and forward unmasked data.
- All Redis keys are org-namespaced to prevent cross-tenant data leakage.
- JWT secrets should be rotated regularly and stored in a secrets manager in production.
- Audit rows are tamper-evident: a per-org SHA-256 hash chain plus a database-level append-only trigger reject any `UPDATE`/`DELETE` on `transactions` or `guardrail_incidents`, regardless of which role issues the statement. `GET /audit/verify` detects the first broken link, if any.
- The auth org/API-key active check fails **closed** by default (`AUTH_FAIL_OPEN_ON_DB_ERROR=false`) — if Postgres is unreachable, the request is blocked (`503`) rather than let a possibly-revoked key through. `config.py` refuses to start in production with this flipped.

## License

Proprietary. All rights reserved.

---

*Built with FastAPI, Presidio, and a healthy distrust of unmasked prompts.*