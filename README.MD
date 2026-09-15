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

## How It Works

```
Your App  →  POST /v1/chat/completions  →  VisorShield  →  OpenAI / Anthropic
                                               │
                                    ┌──────────▼──────────┐
                                    │  1. Auth & RBAC      │
                                    │  2. Rate Limiting    │
                                    │  3. PII Masking      │
                                    │  4. Guardrails       │
                                    │  5. Response Scan    │
                                    │  6. Audit Logging    │
                                    └─────────────────────┘
```

Clients switch from OpenAI to VisorShield by changing **one line**:

```python
# Before
client = OpenAI(base_url="https://api.openai.com/v1")

# After
client = OpenAI(base_url="https://your-visorshield-instance.com/v1")
```

---

## Features

### PII Masking (Prompt & Response)
Detects and replaces sensitive entities before the prompt leaves your infrastructure. Also scans the LLM response — because models can reconstruct PII from context.

### Industry Policy Profiles
Set via a single request header. Four built-in templates:

| Profile | Header Value | Compliance Target |
|---|---|---|
| Healthcare | `healthcare` | HIPAA / Philippine DPA |
| FinTech | `fintech` | PCI-DSS / SEC |
| Government | `govtech` | COA / DILG — includes PhilSys, TIN, SSS |
| Legal / HR | `legal_hr` | Bias & sensitivity filtering |

### Compliance Guardrails
Two-layer policy enforcement:
- **Layer 1** — Fast keyword/regex blocklist (sub-millisecond)
- **Layer 2** — Embedding similarity check against prohibited topic vectors

Example: An LGU chatbot won't give medical advice. A finance bot won't give legal advice. Violations are blocked and logged as incidents.

### Cost Control & Smart Routing
- Per-org monthly token budgets enforced via Redis
- Spike arrest: configurable requests-per-second limit per API key
- Automatic model downgrade for simple prompts (saves cost without degrading output quality)
- Real-time cost tracking per request, per department, per month

### Audit Ledger
Every request is logged with:
- Prompt hash (SHA-256 — raw prompts are never stored)
- PII entity types detected (not the values)
- Model requested vs. model used
- Token counts, cost in USD
- Compliance pass/fail status
- Latency per pipeline step

Built for SOC2 audits, COA transparency requirements, and DPO reviews.

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

```bash
docker exec -i visorshield-api psql $DATABASE_URL < app/db/migrations/001_initial.sql
```

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

```bash
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer <your_jwt>" \
  -H "X-Industry-Type: govtech" \
  -H "X-Org-ID: your-org-uuid" \
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
| `POST` | `/v1/chat/completions` | OpenAI-compatible chat endpoint |
| `GET` | `/health` | Service health check |

### Audit (requires `compliance_officer` or `admin` role)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/audit/transactions` | Paginated transaction log |
| `GET` | `/audit/transactions/{id}` | Single transaction detail |
| `GET` | `/audit/incidents` | Guardrail violation incidents |
| `GET` | `/audit/summary` | Aggregate stats (tokens, cost, PII events, compliance rate) |

### Admin (requires `admin` role)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/admin/organizations` | Create a new organization |
| `POST` | `/admin/api-keys` | Generate API key for an org |
| `GET` | `/admin/organizations/{id}/usage` | Current month usage vs. budget |
| `POST` | `/admin/reports/monthly` | Generate monthly usage summary |

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
| `DEFAULT_PROVIDER` | No | Default: `openai` |
| `FALLBACK_PROVIDER` | No | Default: `anthropic` |
| `EMBEDDING_MODEL` | No | Default: `paraphrase-MiniLM-L6-v2` |
| `LOG_LEVEL` | No | Default: `INFO` |
| `ENVIRONMENT` | No | `development / production` |

*At least one provider key is required.

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
| pgvector upgrade for guardrails (replace in-memory embeddings) | Planned |
| Webhook alerts on quota threshold / guardrail spikes | Planned |
| Multi-region data residency config | Planned |
| De-anonymization (re-inject masked values into response) | Experimental |
| Web dashboard (Next.js) | Separate repo |
| Support for Azure OpenAI endpoint | Planned |
| Streaming response PII scan (real-time chunk scanning) | In progress |

---

## Security Notes

- Raw prompt text is **never stored** anywhere. Only SHA-256 hashes.
- PII values are **never logged**. Only entity type labels (e.g., `"PERSON"`, `"PH_SSS"`).
- The PII engine **fails closed** — any Presidio exception blocks the request. It will never fail silently and forward unmasked data.
- All Redis keys are org-namespaced to prevent cross-tenant data leakage.
- JWT secrets should be rotated regularly and stored in a secrets manager in production.

---

New Endpoints &	What it does:
POST /v1/extension/scan	Steps 1–4 on a captured prompt → masked text + entity map, or 451
POST /v1/extension/response-scan	Step 5 on the assistant's answer; types + placeholders only
GET /v1/extension/policy	Device policy, fail_mode: closed
POST /v1/extension/events	Metadata-only telemetry
POST /v1/extension/heartbeat	Device liveness

## License

Proprietary. All rights reserved.

---

*Built with FastAPI, Presidio, and a healthy distrust of unmasked prompts.*