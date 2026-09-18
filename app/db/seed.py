"""
Seeds realistic, Philippine-context demo data.

Two layers:

1. Metro Pacific BPO Solutions Inc. — the fixed org + API keys that
   ``docs/VisorShield.postman_collection.json`` references by exact UUID.
   These ids must never change; the collection's own JWT-minting script signs
   against them directly (see its ``variable`` block).

2. Four additional single-industry PH tenants, one per policy profile
   (govtech/healthcare/fintech/legal_hr), each with departments, groups,
   users, transactions, and a guardrail incident — so a fresh install has
   something to look at in the Audit and Admin endpoints beyond one BPO.
   GovServe Solutions PH also gets custom Layer-3 pgvector guardrail topics,
   to demonstrate that feature with real embeddings rather than placeholder
   audit rows.

Deliberately routed through the real application code (log_transaction,
log_guardrail_incident, identity_service.get_or_create_user,
inventory_service.record_browser_installation) rather than hand-writing every
INSERT, so the audit hash chain, AI inventory auto-discovery, and Prometheus
counters all end up in the same state a live deployment would produce.

Safe to re-run, with one deliberate exception. Organizations, API keys,
departments, groups, users, browser installations, and policy_embeddings are
all upserted by a deterministic id (uuid5 from stable names) or natural key,
so re-running refreshes them in place rather than duplicating rows.
Transactions and guardrail_incidents are the one exception: this system's
audit tables are append-only by design (see CLAUDE.md "Audit Integrity") —
there is no such thing as upserting a hash-chained row — so re-running this
script appends another batch of the same demo transactions rather than
deduplicating them, exactly as replaying real traffic would.

Usage:
    python -m app.db.seed

Note: if the API process is already running when you seed, its per-org
"does this org have custom guardrail topics" cache (EMBEDDING_CACHE_TTL_SECONDS,
default 300s) may not notice GovServe's new topics immediately — same
staleness window as calling POST .../policy-embeddings against a live org.
"""
import asyncio
import hashlib
import uuid as uuid_mod
from datetime import datetime, timezone

import bcrypt
import structlog
from sqlalchemy import and_, select, text

from app.db.database import AsyncSessionLocal
from app.models.embeddings import PolicyEmbedding
from app.services.audit_service import log_guardrail_incident, log_transaction
from app.services.cost_calculator import calculate_cost
from app.services.identity_service import get_or_create_user
from app.services.inventory_service import record_browser_installation

log = structlog.get_logger()

_SEED_NAMESPACE = uuid_mod.UUID("f1c8e6a0-2f6e-4a8b-9b1d-6b6f3b6c9a10")


def _seed_uuid(*parts: str) -> str:
    """Deterministic id derived from stable parts — same input, same id, every run."""
    return str(uuid_mod.uuid5(_SEED_NAMESPACE, ":".join(parts)))


def _prompt_hash(sample_prompt: str) -> str:
    """
    Stand-in for the real pipeline's hash-of-original-prompt (app/middleware
    /pii_engine.py). The sample prompt text itself is never stored anywhere —
    same as production, only its hash is.
    """
    return hashlib.sha256(sample_prompt.encode()).hexdigest()


# ── Metro Pacific BPO Solutions Inc. — must match the Postman collection ───
ORG_ID = "08a63847-fecb-4698-829a-f71895202a8d"
ORG_NAME = "Metro Pacific BPO Solutions Inc."
ORG_INDUSTRY_TYPE = "govtech"  # the org's own default profile; individual requests can still exercise any profile the JWT's industry_type claim + X-Industry-Type header agree on

# requests_per_second_limit is intentionally generous (not the CreateOrgRequest
# default of 10) — this one org's DB row is the live rate-limit source for
# every role the collection exercises (app/admin/compliance all share it, see
# CLAUDE.md "Never fall back to JWT-only org limits..."), and the collection
# fires requests across four industry-profile examples plus the full Admin
# folder in quick succession.
ORG_REQUESTS_PER_SECOND_LIMIT = 50
ORG_MONTHLY_TOKEN_BUDGET = 5_000_000
ORG_ALLOWED_MODELS = ["gpt-4o-mini", "gpt-4o", "claude-haiku-4-5", "claude-sonnet-4-5"]

API_KEYS = [
    {"id": "b8463e33-a291-4bb7-9720-a65e34a82b88", "label": "Postman Collection — app role"},
    {"id": "04597cb2-367b-4092-bb07-1d3ad098daa6", "label": "Postman Collection — admin role"},
    {"id": "6120edfc-13f2-4d46-accd-81e0ea2b3bd1", "label": "Postman Collection — compliance_officer role"},
    # Left active on purpose: the collection's "Revoke API Key" demo request
    # targets this id by default, so there's something for it to revoke.
    {"id": "4ea96437-3ca3-4c4d-a8a0-73789f8212a1", "label": "Postman Collection — key slated for revocation demo"},
]


# ── Four additional single-industry PH tenants (demo/dev data only) ────────
# Fictitious companies — no resemblance to any real BPO, clinic, bank or law
# firm intended. City/agency names that appear inside sample prompts (e.g.
# "Taguig City Hall") are flavor text for a hypothetical public-facing
# hotline, the same way the Postman collection already uses them; none of
# these seeded organizations claim to BE that government office or bank.
TENANTS = [
    {
        "slug": "govserve",
        "name": "GovServe Solutions PH",
        "industry_type": "govtech",
        "monthly_token_budget": 2_000_000,
        "rps": 20,
        "allowed_models": ["gpt-4o-mini", "gpt-4o"],
        "app_source": "LGU-CitizenPortal",
        "departments": ["LGU Citizen Relations", "Business Permits & Licensing"],
        "groups": ["Compliance Reviewers"],
        "users": [
            {"external_id": "maria.santos@govserve.ph", "display_name": "Maria Santos", "department": "LGU Citizen Relations", "groups": []},
            {"external_id": "ramon.delacruz@govserve.ph", "display_name": "Ramon Dela Cruz", "department": "Business Permits & Licensing", "groups": []},
            {"external_id": "liza.reyes@govserve.ph", "display_name": "Liza Reyes", "department": "LGU Citizen Relations", "groups": ["Compliance Reviewers"]},
        ],
        "transactions": [
            {
                "user": "maria.santos@govserve.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Following up on my Barangay clearance application. Juan Dela Cruz, TIN 123-456-789-000, mobile +63 917 123 4567.",
                "pii": ["PERSON", "PH_TIN", "PHONE_NUMBER"], "status": "masked",
                "input_tokens": 210, "output_tokens": 140,
            },
            {
                "user": "ramon.delacruz@govserve.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Verify business permit renewal for PhilSys ID 1234567890123456, SSS 34-1234567-8.",
                "pii": ["PERSON", "PH_PHILSYS", "PH_SSS"], "status": "masked",
                "input_tokens": 180, "output_tokens": 120,
            },
            {
                "user": "liza.reyes@govserve.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "What are the office hours for the Taguig City Hall business permits window?",
                "pii": [], "status": "pass",
                "input_tokens": 90, "output_tokens": 60,
            },
            {
                "user": "maria.santos@govserve.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Can you help me write campaign material urging residents to vote for Mayor Cruz in the barangay election?",
                "pii": [], "status": "blocked",
                "guardrail_category": "vote for", "guardrail_layer": "keyword",
                "input_tokens": 60, "output_tokens": 0,
            },
        ],
        "custom_guardrail_topics": [
            "partisan political campaigning",
            "election propaganda",
            "solicitation of bribery from a public official",
            "leaking pending COA audit findings",
        ],
        "device": {"user": "maria.santos@govserve.ph", "device_id": _seed_uuid("device", "govserve", "maria"), "extension_version": "1.4.2"},
    },
    {
        "slug": "medassist",
        "name": "MedAssist Philippines Inc.",
        "industry_type": "healthcare",
        "monthly_token_budget": 3_000_000,
        "rps": 20,
        "allowed_models": ["gpt-4o-mini", "gpt-4o", "claude-haiku-4-5"],
        "app_source": "TriageAssist-WebApp",
        "departments": ["Teleconsult Triage", "Patient Records & Billing"],
        "groups": ["Night Shift Nurses"],
        "users": [
            {"external_id": "grace.fernandez@medassist.ph", "display_name": "Grace Fernandez", "department": "Teleconsult Triage", "groups": ["Night Shift Nurses"]},
            {"external_id": "paolo.mendoza@medassist.ph", "display_name": "Paolo Mendoza", "department": "Patient Records & Billing", "groups": []},
            {"external_id": "cathy.lim@medassist.ph", "display_name": "Cathy Lim", "department": "Teleconsult Triage", "groups": []},
        ],
        "transactions": [
            {
                "user": "grace.fernandez@medassist.ph", "provider": "anthropic", "model": "claude-haiku-4-5",
                "sample_prompt": "Patient Ana Villaruel, phone +63 918 555 2210, email ana.v@example.com, reports fever 38.6C for two days. Should she go to the ER?",
                "pii": ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "DATE_TIME"], "status": "masked",
                "input_tokens": 240, "output_tokens": 160,
            },
            {
                "user": "paolo.mendoza@medassist.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Billing inquiry for patient Ramon Bautista, email ramon.bautista@example.com — confirm HMO coverage status.",
                "pii": ["PERSON", "EMAIL_ADDRESS"], "status": "masked",
                "input_tokens": 150, "output_tokens": 90,
            },
            {
                "user": "cathy.lim@medassist.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "What are the clinic's teleconsult hours on weekends?",
                "pii": [], "status": "pass",
                "input_tokens": 70, "output_tokens": 45,
            },
            {
                "user": "grace.fernandez@medassist.ph", "provider": "anthropic", "model": "claude-haiku-4-5",
                "sample_prompt": "Based on these symptoms, diagnose the patient and prescribe medication and dosage.",
                "pii": [], "status": "blocked",
                "guardrail_category": "prescribe", "guardrail_layer": "keyword",
                "input_tokens": 55, "output_tokens": 0,
            },
        ],
        "custom_guardrail_topics": [],
        "device": {"user": "grace.fernandez@medassist.ph", "device_id": _seed_uuid("device", "medassist", "grace"), "extension_version": "1.5.0"},
        # Demonstrates AI inventory's "shadow AI" surface: a nurse used a
        # personal, unmanaged AI tool instead of the sanctioned app above.
        # Seeded via a real transaction so it goes through normal inventory
        # auto-discovery, then explicitly unsanctioned afterward — an admin
        # would do the same via PATCH /admin/inventory/apps/{id}.
        "shadow_transaction": {
            "user": "cathy.lim@medassist.ph", "provider": "openai", "model": "gpt-4o-mini",
            "app_source": "Unmanaged-Personal-ChatGPT",
            "sample_prompt": "Rewrite this discharge summary in simpler English for the patient's family.",
            "pii": ["PERSON"], "status": "masked",
            "input_tokens": 130, "output_tokens": 95,
        },
    },
    {
        "slug": "pacificcrest",
        "name": "Pacific Crest Rural Bank, Inc.",
        "industry_type": "fintech",
        "monthly_token_budget": 2_500_000,
        "rps": 20,
        "allowed_models": ["gpt-4o-mini", "claude-haiku-4-5"],
        "app_source": "CollectionsDesk-CRM",
        "departments": ["Collections & Recovery", "Fraud & Compliance"],
        "groups": ["Senior Compliance Reviewers"],
        "users": [
            {"external_id": "arnel.tan@pacificcrestbank.ph", "display_name": "Arnel Tan", "department": "Collections & Recovery", "groups": []},
            {"external_id": "ivy.gonzales@pacificcrestbank.ph", "display_name": "Ivy Gonzales", "department": "Fraud & Compliance", "groups": ["Senior Compliance Reviewers"]},
            {"external_id": "ben.uy@pacificcrestbank.ph", "display_name": "Ben Uy", "department": "Collections & Recovery", "groups": []},
        ],
        "transactions": [
            {
                "user": "arnel.tan@pacificcrestbank.ph", "provider": "anthropic", "model": "claude-haiku-4-5",
                "sample_prompt": "Customer Rosario Panganiban wants a payment plan. Card ends 4111 1111 1111 1111, TIN 123-456-789-000 for verification.",
                "pii": ["PERSON", "CREDIT_CARD", "PH_TIN"], "status": "masked",
                "input_tokens": 200, "output_tokens": 130,
            },
            {
                "user": "ben.uy@pacificcrestbank.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Loan verification for Teresa Ocampo, TIN 456-789-123-000 — confirm outstanding balance.",
                "pii": ["PERSON", "PH_TIN"], "status": "masked",
                "input_tokens": 160, "output_tokens": 100,
            },
            {
                "user": "ivy.gonzales@pacificcrestbank.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "What are today's branch operating hours for the Makati branch?",
                "pii": [], "status": "pass",
                "input_tokens": 65, "output_tokens": 40,
            },
            {
                "user": "arnel.tan@pacificcrestbank.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Tell this customer we guarantee returns of 20% a month if they roll their overdue balance into our investment product.",
                "pii": [], "status": "blocked",
                "guardrail_category": "guaranteed returns", "guardrail_layer": "keyword",
                "input_tokens": 58, "output_tokens": 0,
            },
        ],
        "custom_guardrail_topics": [],
        "device": None,
    },
    {
        "slug": "manilabay",
        "name": "Manila Bay Legal & HR Advisory",
        "industry_type": "legal_hr",
        "monthly_token_budget": 1_500_000,
        "rps": 15,
        "allowed_models": ["gpt-4o-mini"],
        "app_source": "HRHelpdesk-Bot",
        "departments": ["Employee Relations", "Payroll & Benefits"],
        "groups": ["HR Business Partners"],
        "users": [
            {"external_id": "jasmine.cruz@manilabayhr.ph", "display_name": "Jasmine Cruz", "department": "Employee Relations", "groups": ["HR Business Partners"]},
            {"external_id": "victor.aquino@manilabayhr.ph", "display_name": "Victor Aquino", "department": "Payroll & Benefits", "groups": []},
            {"external_id": "nora.bautista@manilabayhr.ph", "display_name": "Nora Bautista", "department": "Employee Relations", "groups": []},
        ],
        "transactions": [
            {
                "user": "jasmine.cruz@manilabayhr.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Employee Mark Villanueva, age 34, email mark.v@example.com, is asking about maternity leave for his spouse.",
                "pii": ["PERSON", "AGE", "EMAIL_ADDRESS"], "status": "masked",
                "input_tokens": 180, "output_tokens": 110,
            },
            {
                "user": "victor.aquino@manilabayhr.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "13th month pay computation question from employee Divina Ramos, phone +63 920 444 1122.",
                "pii": ["PERSON", "PHONE_NUMBER"], "status": "masked",
                "input_tokens": 140, "output_tokens": 85,
            },
            {
                "user": "nora.bautista@manilabayhr.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "What is the standard onboarding checklist for new hires?",
                "pii": [], "status": "pass",
                "input_tokens": 60, "output_tokens": 50,
            },
            {
                "user": "jasmine.cruz@manilabayhr.ph", "provider": "openai", "model": "gpt-4o-mini",
                "sample_prompt": "Draft a job posting that says applicants must be no older than 30 years old.",
                "pii": [], "status": "blocked",
                "guardrail_category": "no older than", "guardrail_layer": "keyword",
                "input_tokens": 50, "output_tokens": 0,
            },
        ],
        "custom_guardrail_topics": [],
        "device": None,
    },
]


async def _upsert_organization(org_id: str, name: str, industry_type: str, budget: int, rps: int, models: list) -> None:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        await session.execute(
            text(
                "INSERT INTO organizations "
                "(id, name, industry_type, monthly_token_budget, requests_per_second_limit, allowed_models, is_active, created_at) "
                "VALUES (:id, :name, :industry_type, :budget, :rps, :models, true, :now) "
                "ON CONFLICT (id) DO UPDATE SET "
                "name = :name, industry_type = :industry_type, monthly_token_budget = :budget, "
                "requests_per_second_limit = :rps, allowed_models = :models, is_active = true"
            ),
            {"id": org_id, "name": name, "industry_type": industry_type, "budget": budget, "rps": rps, "models": models, "now": now},
        )
        await session.commit()
    log.info("seed_organization_upserted", org_id=org_id, name=name)


async def _seed_metro_pacific() -> None:
    await _upsert_organization(ORG_ID, ORG_NAME, ORG_INDUSTRY_TYPE, ORG_MONTHLY_TOKEN_BUDGET, ORG_REQUESTS_PER_SECOND_LIMIT, ORG_ALLOWED_MODELS)

    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        for key in API_KEYS:
            # key_hash is never actually checked in this system's auth flow —
            # the JWT's `sub` claim IS the api_key id (see auth.py), and the
            # raw key returned by POST /admin/api-keys is only ever shown
            # once for the admin's own records. Still hashed, not stored raw,
            # to match the schema's intent for any future flow that does
            # present a raw key. Re-running this script doesn't rehash it —
            # the ON CONFLICT below leaves key_hash untouched on an update.
            placeholder_raw_key = f"vs_seed_{key['id']}"
            key_hash = bcrypt.hashpw(placeholder_raw_key.encode(), bcrypt.gensalt()).decode()

            await session.execute(
                text(
                    "INSERT INTO api_keys (id, org_id, key_hash, label, is_active, created_at) "
                    "VALUES (:id, :org_id, :key_hash, :label, true, :now) "
                    "ON CONFLICT (id) DO UPDATE SET "
                    "org_id = :org_id, label = :label, is_active = true"
                ),
                {"id": key["id"], "org_id": ORG_ID, "key_hash": key_hash, "label": key["label"], "now": now},
            )
            log.info("seed_api_key_upserted", key_id=key["id"], label=key["label"])
        await session.commit()


async def _upsert_named_rows(table: str, org_id: str, names: list) -> dict:
    """Upsert departments/groups by (org_id, name) with a deterministic id; return {name: id}."""
    ids = {}
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        for name in names:
            row_id = _seed_uuid(table, org_id, name)
            await session.execute(
                text(
                    f"INSERT INTO {table} (id, org_id, name, created_at) VALUES (:id, :org_id, :name, :now) "
                    "ON CONFLICT (id) DO UPDATE SET name = :name"
                ),
                {"id": row_id, "org_id": org_id, "name": name, "now": now},
            )
            ids[name] = row_id
        await session.commit()
    return ids


async def _seed_tenant_identity(org_id: str, tenant: dict) -> dict:
    """Departments, groups, users (auto-provision + curate). Returns {external_id: user_id}."""
    dept_ids = await _upsert_named_rows("departments", org_id, tenant["departments"])
    group_ids = await _upsert_named_rows("groups", org_id, tenant["groups"])

    user_ids = {}
    for u in tenant["users"]:
        identity = await get_or_create_user(org_id, u["external_id"])
        if identity is None:
            log.warning("seed_user_upsert_failed", org_id=org_id, external_id=u["external_id"])
            continue
        user_id = identity["id"]
        user_ids[u["external_id"]] = user_id

        # Auto-provisioning only sets external_id/timestamps — curate the rest
        # the way an admin would via PATCH /admin/users/{id}.
        async with AsyncSessionLocal() as session:
            await session.execute(
                text(
                    "UPDATE users SET display_name = :display_name, email = :email, department_id = :department_id "
                    "WHERE id = :id"
                ),
                {
                    "display_name": u["display_name"],
                    "email": u["external_id"],
                    "department_id": dept_ids.get(u["department"]) if u.get("department") else None,
                    "id": user_id,
                },
            )
            for group_name in u.get("groups", []):
                group_id = group_ids.get(group_name)
                if not group_id:
                    continue
                await session.execute(
                    text(
                        "INSERT INTO user_group_memberships (user_id, group_id, created_at) "
                        "VALUES (:user_id, :group_id, :now) ON CONFLICT DO NOTHING"
                    ),
                    {"user_id": user_id, "group_id": group_id, "now": datetime.now(timezone.utc)},
                )
            await session.commit()

    return user_ids


async def _seed_tenant_transactions(org_id: str, tenant: dict, user_ids: dict) -> None:
    industry_type = tenant["industry_type"]
    for tx in tenant["transactions"]:
        cost = calculate_cost(tx["model"], tx["input_tokens"], tx["output_tokens"])
        user_id = user_ids.get(tx["user"])
        blocked = tx["status"] == "blocked"

        transaction_id = await log_transaction(
            org_id=org_id,
            app_source=tenant["app_source"],
            model_requested=tx["model"],
            model_used="" if blocked else tx["model"],
            provider="" if blocked else tx["provider"],
            prompt_hash=_prompt_hash(tx["sample_prompt"]),
            pii_detected=tx["pii"],
            response_pii_detected=[],
            input_tokens=tx["input_tokens"],
            output_tokens=0 if blocked else tx["output_tokens"],
            cost_usd=0.0 if blocked else cost,
            compliance_status=tx["status"],
            guardrail_triggered=tx.get("guardrail_category"),
            latency_ms=180 if blocked else 640,
            industry_type=industry_type,
            routing_reason="guardrail_block" if blocked else "normal_routing",
            user_id=user_id,
            external_user_id=tx["user"],
        )

        if blocked:
            await log_guardrail_incident(
                org_id=org_id,
                transaction_id=transaction_id,
                policy_profile=industry_type,
                violation_category=tx["guardrail_category"],
                detection_layer=tx["guardrail_layer"],
                prompt_hash=_prompt_hash(tx["sample_prompt"]),
            )

    shadow = tenant.get("shadow_transaction")
    if shadow:
        cost = calculate_cost(shadow["model"], shadow["input_tokens"], shadow["output_tokens"])
        await log_transaction(
            org_id=org_id,
            app_source=shadow["app_source"],
            model_requested=shadow["model"],
            model_used=shadow["model"],
            provider=shadow["provider"],
            prompt_hash=_prompt_hash(shadow["sample_prompt"]),
            pii_detected=shadow["pii"],
            response_pii_detected=[],
            input_tokens=shadow["input_tokens"],
            output_tokens=shadow["output_tokens"],
            cost_usd=cost,
            compliance_status=shadow["status"],
            guardrail_triggered=None,
            latency_ms=610,
            industry_type=industry_type,
            routing_reason="normal_routing",
            user_id=user_ids.get(shadow["user"]),
            external_user_id=shadow["user"],
        )
        # The point of this row: an app nobody sanctioned actually got used.
        # An admin would flip this the same way, via
        # PATCH /admin/inventory/apps/{id} {"is_sanctioned": false}.
        async with AsyncSessionLocal() as session:
            await session.execute(
                text("UPDATE ai_apps SET is_sanctioned = false WHERE org_id = :org_id AND app_source = :app_source"),
                {"org_id": org_id, "app_source": shadow["app_source"]},
            )
            await session.commit()
        log.info("seed_shadow_app_flagged", org_id=org_id, app_source=shadow["app_source"])


async def _seed_tenant_guardrail_topics(org_id: str, topics: list) -> None:
    if not topics:
        return
    try:
        from app.middleware.guardrails import get_embedding_model
    except Exception as exc:
        log.warning("seed_guardrail_topics_skipped_import_failed", org_id=org_id, error=str(exc))
        return

    try:
        loop = asyncio.get_event_loop()
        model = get_embedding_model()
        embeddings = await loop.run_in_executor(None, lambda: model.encode(topics, normalize_embeddings=True))
    except Exception as exc:
        # Best-effort: a missing/undownloaded embedding model must not abort
        # the rest of the seed run, which is far more commonly what's needed.
        log.warning("seed_guardrail_topics_skipped_embedding_failed", org_id=org_id, error=str(exc))
        return

    org_uuid = uuid_mod.UUID(org_id)
    async with AsyncSessionLocal() as session:
        for topic, emb in zip(topics, embeddings):
            existing = await session.execute(
                select(PolicyEmbedding).where(
                    and_(
                        PolicyEmbedding.org_id == org_uuid,
                        PolicyEmbedding.policy_profile == "govtech",
                        PolicyEmbedding.topic == topic,
                    )
                )
            )
            row = existing.scalar_one_or_none()
            if row:
                row.embedding = emb.tolist()
                row.updated_at = datetime.now(timezone.utc)
            else:
                session.add(
                    PolicyEmbedding(org_id=org_uuid, policy_profile="govtech", topic=topic, embedding=emb.tolist())
                )
        await session.commit()
    log.info("seed_guardrail_topics_upserted", org_id=org_id, count=len(topics))


async def _seed_tenant(tenant: dict) -> str:
    org_id = _seed_uuid("org", tenant["slug"])
    await _upsert_organization(
        org_id, tenant["name"], tenant["industry_type"], tenant["monthly_token_budget"], tenant["rps"], tenant["allowed_models"]
    )

    # One app-role API key per tenant so it's independently callable, not
    # just visible in the audit/admin endpoints.
    key_id = _seed_uuid("api_key", tenant["slug"], "app")
    async with AsyncSessionLocal() as session:
        placeholder_raw_key = f"vs_seed_{key_id}"
        key_hash = bcrypt.hashpw(placeholder_raw_key.encode(), bcrypt.gensalt()).decode()
        await session.execute(
            text(
                "INSERT INTO api_keys (id, org_id, key_hash, label, is_active, created_at) "
                "VALUES (:id, :org_id, :key_hash, :label, true, :now) "
                "ON CONFLICT (id) DO UPDATE SET org_id = :org_id, label = :label, is_active = true"
            ),
            {"id": key_id, "org_id": org_id, "key_hash": key_hash, "label": f"{tenant['name']} — app role", "now": datetime.now(timezone.utc)},
        )
        await session.commit()

    user_ids = await _seed_tenant_identity(org_id, tenant)
    await _seed_tenant_transactions(org_id, tenant, user_ids)
    await _seed_tenant_guardrail_topics(org_id, tenant.get("custom_guardrail_topics", []))

    device = tenant.get("device")
    if device:
        await record_browser_installation(
            org_id=org_id,
            device_id=device["device_id"],
            extension_version=device["extension_version"],
            user_id=user_ids.get(device["user"]),
        )

    log.info("seed_tenant_complete", org_id=org_id, name=tenant["name"], industry_type=tenant["industry_type"])
    return org_id


async def seed() -> None:
    await _seed_metro_pacific()

    tenant_org_ids = {}
    for tenant in TENANTS:
        tenant_org_ids[tenant["slug"]] = await _seed_tenant(tenant)

    print(f"Seeded org {ORG_NAME!r} ({ORG_ID}) and {len(API_KEYS)} API keys.")
    print("These ids match docs/VisorShield.postman_collection.json's collection variables —")
    print("set jwt_secret there to your JWT_SECRET and the collection is ready to run.")
    print()
    print("Seeded 4 additional PH tenants (departments, groups, users, transactions, incidents):")
    for tenant in TENANTS:
        print(f"  - {tenant['name']} ({tenant['industry_type']}): org_id={tenant_org_ids[tenant['slug']]}")
    print()
    print("Mint a JWT for any of these with sub=<its api_key id>, org_id=<its org_id>,")
    print("industry_type=<its industry_type>, role='app' (see CLAUDE.md JWT Claims Schema).")


if __name__ == "__main__":
    asyncio.run(seed())
