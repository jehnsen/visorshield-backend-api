# VisorShield — Architecture Overview

This is a narrative walkthrough of how a request actually moves through the
system, for engineers who are new to the codebase. `README.md` is the
pitch and quick start; `CLAUDE.md` is the authoritative rule book (pipeline
order, failure modes, "what not to do"). This document sits between them:
enough detail to understand *why* the pieces are shaped the way they are,
without duplicating either file line-for-line. When this document and
`CLAUDE.md` disagree, `CLAUDE.md` wins — update this file to match.

---

## What problem this solves

Employees paste sensitive data into AI chat tools constantly, and without a
gateway in front of that traffic, an organization has no visibility into it
and no way to stop it. VisorShield sits in two places:

1. **In front of your own app's LLM calls** — `POST /v1/chat/completions`,
   an OpenAI-compatible proxy. Point your app at VisorShield instead of
   OpenAI/Anthropic directly; nothing else about your integration changes.
2. **In front of ad-hoc browser use** — `POST /v1/extension/*`, called by a
   companion browser extension for staff who paste prompts straight into
   chatgpt.com. VisorShield never touches that network path directly; it
   scans and hands back a masked version for the extension to type into the
   page.

Both surfaces run the same core pipeline, so policy is defined once and
enforced consistently regardless of how the prompt reached VisorShield.

---

## The request lifecycle (proxy path)

```
Client                VisorShield                                    Provider
  │                        │
  │  POST /v1/chat/        │
  │  completions           │
  ├───────────────────────►│
  │                    [1] auth.py
  │                        │  JWT valid? X-Industry-Type matches the
  │                        │  token's industry_type claim? Load live
  │                        │  org/key row from Postgres (fail-closed
  │                        │  if that DB read fails) — its
  │                        │  allowed_models / requests_per_second /
  │                        │  monthly_token_budget win over the JWT's.
  │                        │
  │                    [2] rate_limit.py
  │                        │  Redis: per-second spike arrest +
  │                        │  monthly token quota, both org-namespaced.
  │                        │
  │                    [3] pii_engine.py
  │                        │  Presidio, using the industry template
  │                        │  the org's policy_profile selects. Any
  │                        │  exception here blocks the request (500) —
  │                        │  this step never fails open. The
  │                        │  placeholder→original map is kept only in
  │                        │  request.state, for step 5's rehydration.
  │                        │
  │                    [4] guardrails.py
  │                        │  Three layers, first hit blocks (451):
  │                        │  keyword blocklist → prompt-injection
  │                        │  heuristics → embedding similarity
  │                        │  (per-org pgvector topics, else defaults).
  │                        │
  │                        ├───────────────────────────────────────────►│
  │                        │         sanitized prompt                   │
  │                        │◄───────────────────────────────────────────┤
  │                        │
  │                    [5] response_scanner.py
  │                        │  Presidio scans the model's answer for
  │                        │  PII it may have introduced or echoed
  │                        │  back, masks it — then (if enabled)
  │                        │  rehydrate_pii() restores the caller's
  │                        │  OWN masked values. That order is load-
  │                        │  bearing: mask what the model said first,
  │                        │  then restore what the caller said.
  │                        │
  │                   Audit Logger
  │                        │  asyncio.create_task(...) — fire-and-
  │                        │  forget, hash-chained, never awaited in
  │                        │  the request path.
  │◄───────────────────────┤
  │   masked response +    │
  │   X-VisorShield-*      │
  │   headers               │
```

Streaming (SSE) requests run the identical pipeline, but the provider's
streamed output is buffered in full before step 5 runs — there is no
per-chunk PII scan. The tradeoff is explicit: correctness of the PII
boundary over time-to-first-token.

Every step's execution time lands in `request.state.pipeline_timing`, summed
into `latency_ms` on the audit record and also exported per-step as a
Prometheus histogram (`visorshield_pipeline_step_duration_ms`).

**Why this order, specifically:** auth before rate-limiting means an invalid
caller is rejected before it can consume quota. Rate-limiting before PII
scanning means a caller that's already over budget doesn't pay the cost of
an NLP pass. PII masking before guardrails means the guardrail's keyword and
embedding checks run against a prompt that's already safe to have logged
metadata about. None of this is incidental — see `CLAUDE.md`'s Interceptor
Pipeline Order section for the line "this order is non-negotiable."

---

## Guardrails: why three layers

A single detection method is easy to defeat. Layer 1 (keyword/regex) catches
the obvious case for free. Layer 2 (prompt-injection heuristics) exists
because a masked, policy-clean prompt can still be an attempt to override the
system prompt or exfiltrate instructions — a different threat model than
"topic the org doesn't want discussed." Layer 3 (embedding similarity)
catches paraphrases layers 1–2 can't: a keyword list can't anticipate every
way to ask for medical advice, but "give me a diagnosis for these symptoms"
and "what's this rash, doctor?" land near each other in embedding space.

Layer 3's per-org customization (`policy_embeddings`, pgvector, ivfflat
cosine index) exists because the built-in default topics are a reasonable
starting point, not a complete list for every org's actual risk surface — an
admin can add topics specific to their business without a code change or
redeploy. The presence check ("does this org have any custom topics at all")
is cached for `EMBEDDING_CACHE_TTL_SECONDS`; the actual nearest-neighbor
search always hits Postgres live, so correctness doesn't depend on cache
invalidation timing, only the *decision to check the DB at all* does.

---

## Identity, inventory, and "what is actually happening here"

Two things were true before this layer existed: every call under a shared
app/API key was indistinguishable from every other, and there was no record
of which providers, models, or calling applications were actually in use.
Both are governance blind spots for a product whose entire premise is
visibility.

- **Identity** (`X-VisorShield-User` → `User` row, `app/models/identity.py`)
  closes the first gap. It's deliberately *not* authentication — VisorShield
  trusts whatever identifier the calling app already uses (SSO subject,
  email, employee ID) and just tracks it. Resolution fails open (a DB hiccup
  degrades to `user_id: None`, `external_user_id` still recorded) because
  it's an enrichment layer; the org/API-key check remains the actual
  security gate and stays fail-closed.
- **AI Inventory** (`app/models/inventory.py`) closes the second. Providers,
  models, calling apps, and browser installations are all upserted from
  observed traffic — nothing is hand-entered, so the inventory can't drift
  from reality the way a manually maintained spreadsheet does. `is_sanctioned`
  is a governance flag an admin sets after seeing what showed up, not a
  pricing or access-control source (that's still `cost_calculator.py` and
  `allowed_models` respectively).

---

## Audit integrity: what "immutable" actually means here

Plain Postgres rows are only as immutable as the DB permissions around them
— any admin (or anyone with DB credentials) can `UPDATE` them with no trace.
Two mechanisms back the "immutable audit" claim instead of just asserting it:

1. A **hash chain**: every `Transaction` and `GuardrailIncident` commits to
   `record_hash = sha256(prev_hash || canonical_fields)`, chained per-org via
   an anchor row locked with `SELECT ... FOR UPDATE` on append (so concurrent
   fire-and-forget writes for the same org can't race and fork the chain).
   Edit a row after the fact and its own hash — and every later link — breaks.
   `GET /audit/verify` recomputes the chain and reports the first break.
2. An **append-only trigger** at the database engine level
   (`prevent_audit_mutation()`) that rejects `UPDATE`/`DELETE` on
   `transactions` and `guardrail_incidents` outright, regardless of which
   role issues the statement.

The honest boundary: this doesn't survive a superuser dropping the trigger
and hand-editing history to match new hashes — no application-layer
mechanism can prevent that. What it closes is routine admin access or a
compromised app credential quietly rewriting the record after the fact,
which is the realistic threat this kind of audit trail defends against.

---

## Two entry points, one pipeline

`app/routers/extension.py` reuses steps 1–4 exactly — same `auth_middleware`,
same `rate_limit_middleware`, same Presidio scan, same three-layer
guardrails — because policy has to be identical regardless of which surface
a prompt arrives through. What differs is what happens with the result: the
proxy forwards the sanitized prompt to a provider and returns its answer; the
extension surface returns the masked prompt and the placeholder→original map
directly to the caller, because there's no completion to make — the browser
extension types the masked text into the page itself. That also means
extension-sourced audit rows record zero tokens and no provider: a scan is a
compliance event, not a spend event, and the audit schema reflects that
distinction rather than faking token counts that don't exist.

---

## Where to look next

| Question | Start here |
|---|---|
| What's the exact pipeline order and failure behavior per step? | `CLAUDE.md` → Interceptor Pipeline Order, Failure Modes |
| How do I add a new industry policy profile? | `CLAUDE.md` → Common Tasks |
| How do I set custom guardrail topics for an org? | `CLAUDE.md` → Guardrails: Three-Layer Detection, Common Tasks |
| What's the full request/response contract? | `README.md` → API Reference, or `docs/VisorShield.postman_collection.json` |
| How is pricing computed? | `app/services/cost_calculator.py` (single source of truth — see `CLAUDE.md` → LLM Cost Routing Rules) |
| How do I verify the audit log hasn't been tampered with? | `GET /audit/verify`, `CLAUDE.md` → Audit Integrity |
