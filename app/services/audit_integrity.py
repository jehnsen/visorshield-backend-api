"""
Tamper-evident hash chain for the transactions audit log.

Before this, "immutable audit" was aspirational: plain Postgres rows any
admin (or anyone with DB creds) could UPDATE with no trace. Two mechanisms
close that gap:

1. Each Transaction commits to a running per-org hash chain (this module) —
   ``record_hash = sha256(prev_hash || canonical_fields)``. Editing a row after
   the fact breaks its own hash and every later link, and /audit/verify
   proves that computationally rather than by policy.
2. A DB trigger (see the migration) rejects UPDATE/DELETE on ``transactions``
   and ``guardrail_incidents`` outright — append-only at the engine level, not
   just by application convention.

Neither survives a superuser dropping the trigger and hand-editing rows and
prior links to match; that is the accepted boundary of DB-level WORM (the
same boundary standard Postgres audit-trigger extensions operate under). What
it does close is the actual reported gap: routine admin access, or a
compromised app credential, can no longer quietly edit history.
"""
import hashlib
import json
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_GENESIS = "genesis"


def _canon_cost(cost_usd: Any) -> str:
    if cost_usd is None:
        return "0.00000000"
    return f"{float(cost_usd):.8f}"


def _canon_list(values: Optional[List[str]]) -> List[str]:
    return sorted(values) if values else []


def _canon_created_at(created_at: Any) -> str:
    if isinstance(created_at, datetime):
        return created_at.isoformat()
    return str(created_at)


def canonical_transaction_fields(
    *,
    id: uuid.UUID,
    org_id: uuid.UUID,
    app_source: Optional[str],
    model_requested: Optional[str],
    model_used: Optional[str],
    provider: Optional[str],
    prompt_hash: Optional[str],
    pii_detected: Optional[List[str]],
    response_pii_detected: Optional[List[str]],
    input_tokens: Optional[int],
    output_tokens: Optional[int],
    cost_usd: Any,
    compliance_status: Optional[str],
    guardrail_triggered: Optional[str],
    latency_ms: Optional[int],
    industry_type: Optional[str],
    routing_reason: Optional[str],
    user_id: Optional[uuid.UUID],
    external_user_id: Optional[str],
    created_at: Any,
) -> Dict[str, Any]:
    """
    Normalize a transaction's evidentiary fields into the exact plain-value
    shape that gets hashed. Called identically at write time (from Python
    kwargs) and at verify time (from an ORM row's attributes) so both sides
    produce the same bytes for the same logical record.
    """
    return {
        "id": str(id),
        "org_id": str(org_id),
        "app_source": app_source or "",
        "model_requested": model_requested or "",
        "model_used": model_used or "",
        "provider": provider or "",
        "prompt_hash": prompt_hash or "",
        "pii_detected": _canon_list(pii_detected),
        "response_pii_detected": _canon_list(response_pii_detected),
        "input_tokens": int(input_tokens or 0),
        "output_tokens": int(output_tokens or 0),
        "cost_usd": _canon_cost(cost_usd),
        "compliance_status": compliance_status or "",
        "guardrail_triggered": guardrail_triggered or "",
        "latency_ms": int(latency_ms or 0),
        "industry_type": industry_type or "",
        "routing_reason": routing_reason or "",
        "user_id": str(user_id) if user_id else "",
        "external_user_id": external_user_id or "",
        "created_at": _canon_created_at(created_at),
    }


def _hash_link(prev_hash: Optional[str], fields: Dict[str, Any]) -> str:
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256((prev_hash or _GENESIS).encode() + b"|" + payload).hexdigest()


async def append_chain_link(
    session: AsyncSession, org_id: uuid.UUID, fields: Dict[str, Any]
) -> Tuple[str, Optional[str], int]:
    """
    Reserve the next slot in this org's hash chain and return
    (record_hash, prev_hash, chain_seq) for the caller to store on the new
    Transaction row. Must run in the same DB transaction as that row's insert.

    The upsert-then-lock pattern avoids a race on an org's very first
    transaction: two concurrent writers doing SELECT-then-INSERT on a missing
    anchor row would both try to create it. ON CONFLICT DO NOTHING makes the
    anchor's existence idempotent, then FOR UPDATE serializes the actual
    chain advance.
    """
    await session.execute(
        text(
            "INSERT INTO audit_chain_state (org_id, last_seq, last_hash) "
            "VALUES (:org_id, 0, NULL) ON CONFLICT (org_id) DO NOTHING"
        ),
        {"org_id": str(org_id)},
    )
    row = (
        await session.execute(
            text(
                "SELECT last_seq, last_hash FROM audit_chain_state "
                "WHERE org_id = :org_id FOR UPDATE"
            ),
            {"org_id": str(org_id)},
        )
    ).one()

    prev_hash = row.last_hash
    chain_seq = row.last_seq + 1
    record_hash = _hash_link(prev_hash, fields)

    await session.execute(
        text(
            "UPDATE audit_chain_state SET last_seq = :seq, last_hash = :hash "
            "WHERE org_id = :org_id"
        ),
        {"seq": chain_seq, "hash": record_hash, "org_id": str(org_id)},
    )

    return record_hash, prev_hash, chain_seq


def recompute_record_hash(fields: Dict[str, Any], prev_hash: Optional[str]) -> str:
    """Used by /audit/verify to recompute a stored row's hash from its own fields."""
    return _hash_link(prev_hash, fields)
