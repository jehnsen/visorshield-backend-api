import re
import time
import asyncio
import structlog
import numpy as np
from typing import List, Optional, Tuple, Dict
from fastapi import Request, HTTPException
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, and_
from app.policies import get_policy
from app.config import settings

log = structlog.get_logger()

_embedding_model: SentenceTransformer | None = None

# In-memory cache: key = (org_id, policy_name), value = (embeddings_array, topics_list, expiry_ts)
_db_embedding_cache: Dict[str, Tuple[np.ndarray, List[str], float]] = {}

# Default policy embeddings (in-process, computed once at warm-up)
_default_embeddings_cache: Dict[str, np.ndarray] = {}


def get_embedding_model() -> SentenceTransformer:
    global _embedding_model
    if _embedding_model is None:
        _embedding_model = SentenceTransformer(settings.EMBEDDING_MODEL)
    return _embedding_model


def warmup_embeddings() -> None:
    """Pre-compute embeddings for all default policy profiles. Called at startup."""
    from app.policies import POLICY_REGISTRY
    model = get_embedding_model()
    for policy_name, policy in POLICY_REGISTRY.items():
        if policy_name not in _default_embeddings_cache:
            embs = model.encode(policy.prohibited_topics, normalize_embeddings=True)
            _default_embeddings_cache[policy_name] = embs
            log.info("embeddings_warmed", policy=policy_name, topics=len(policy.prohibited_topics))


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-10))


async def _load_db_embeddings(
    org_id: str, policy_name: str
) -> Optional[Tuple[np.ndarray, List[str]]]:
    """
    Load org-specific policy embeddings from pgvector.
    Returns (embeddings_matrix, topics) or None if no DB entries exist.
    Uses a TTL cache to avoid a DB round-trip on every request.
    """
    cache_key = f"{org_id}:{policy_name}"
    now = time.monotonic()

    cached = _db_embedding_cache.get(cache_key)
    if cached is not None:
        embs, topics, expiry = cached
        if now < expiry:
            return (embs, topics) if len(topics) > 0 else None
        del _db_embedding_cache[cache_key]

    try:
        from app.db.database import AsyncSessionLocal
        from app.models.embeddings import PolicyEmbedding
        import uuid as _uuid

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(PolicyEmbedding.topic, PolicyEmbedding.embedding).where(
                    and_(
                        PolicyEmbedding.org_id == _uuid.UUID(org_id),
                        PolicyEmbedding.policy_profile == policy_name,
                    )
                )
            )
            rows = result.all()

        if not rows:
            # Cache the "no entries" result to avoid hammering DB
            _db_embedding_cache[cache_key] = (
                np.array([]),
                [],
                now + settings.EMBEDDING_CACHE_TTL_SECONDS,
            )
            return None

        topics = [r.topic for r in rows]
        embs = np.array([r.embedding for r in rows], dtype=np.float32)
        # Normalise in case stored vectors aren't unit-length
        norms = np.linalg.norm(embs, axis=1, keepdims=True)
        embs = embs / (norms + 1e-10)

        _db_embedding_cache[cache_key] = (embs, topics, now + settings.EMBEDDING_CACHE_TTL_SECONDS)
        return (embs, topics)

    except Exception as exc:
        log.warning("db_embedding_load_failed", error=str(exc), org_id=org_id, policy=policy_name)
        return None


def invalidate_embedding_cache(org_id: str, policy_name: str) -> None:
    """Call this after upserting policy embeddings via the admin API."""
    cache_key = f"{org_id}:{policy_name}"
    _db_embedding_cache.pop(cache_key, None)


def _check_keyword_blocklist(text: str, blocklist: List[str]) -> Optional[str]:
    text_lower = text.lower()
    for keyword in blocklist:
        if keyword.lower() in text_lower:
            return keyword
    return None


def _check_embedding_similarity(
    prompt_embedding: np.ndarray,
    embs: np.ndarray,
    topics: List[str],
    threshold: float = 0.72,
) -> Optional[str]:
    best_score = 0.0
    best_topic = None
    for topic, emb in zip(topics, embs):
        score = _cosine_similarity(prompt_embedding, emb)
        if score > best_score:
            best_score = score
            best_topic = topic
    return best_topic if best_score >= threshold else None


def _extract_prompt_text(body) -> str:
    parts = []
    for msg in body.messages:
        if isinstance(msg.content, str):
            parts.append(msg.content)
        elif isinstance(msg.content, list):
            for part in msg.content:
                if isinstance(part, dict) and part.get("type") == "text":
                    parts.append(part["text"])
    return " ".join(parts)


async def guardrails_middleware(request: Request) -> None:
    """
    Step 4: Two-layer compliance guardrail check.
    Layer 1 — keyword/regex blocklist (fast, synchronous).
    Layer 2 — embedding similarity. Uses pgvector per-org embeddings when available,
               falls back to default in-process embeddings.
    Returns HTTP 451 on violation.
    """
    start = time.monotonic()

    industry_type = request.headers.get("X-Industry-Type", "")
    policy = get_policy(industry_type)
    request_id = getattr(request.state, "request_id", "")
    org_id = getattr(request.state, "jwt_claims", {}).get("org_id", "unknown")

    if not policy:
        request.state.pipeline_timing["guardrails"] = (time.monotonic() - start) * 1000
        return

    body = getattr(request.state, "parsed_body", None)
    if body is None:
        return

    prompt_text = _extract_prompt_text(body)
    prompt_hash = getattr(request.state, "prompt_hash", "")

    # ── Layer 1: Keyword blocklist ──────────────────────────────────────────
    keyword_hit = _check_keyword_blocklist(prompt_text, policy.keyword_blocklist)
    if keyword_hit:
        _set_state_and_raise(request, keyword_hit, policy.name, start, "keyword")

    # ── Layer 2: Embedding similarity ───────────────────────────────────────
    model = get_embedding_model()
    prompt_embedding = model.encode([prompt_text], normalize_embeddings=True)[0]

    # Try org-specific pgvector embeddings first
    db_result = await _load_db_embeddings(org_id, policy.name)

    if db_result is not None:
        embs, topics = db_result
        topic_hit = _check_embedding_similarity(prompt_embedding, embs, topics)
        source = "pgvector"
    else:
        # Fall back to default in-process embeddings
        default_embs = _default_embeddings_cache.get(policy.name)
        if default_embs is None:
            # Warm up on-demand (first request before lifespan ran, e.g. in tests)
            default_embs = model.encode(policy.prohibited_topics, normalize_embeddings=True)
            _default_embeddings_cache[policy.name] = default_embs
        topic_hit = _check_embedding_similarity(prompt_embedding, default_embs, policy.prohibited_topics)
        source = "in_process"

    if topic_hit:
        log.warning(
            "guardrail_triggered",
            layer="embedding",
            source=source,
            violation=topic_hit,
            policy=policy.name,
            org_id=org_id,
            request_id=request_id,
            pipeline_step="guardrails",
        )
        _set_state_and_raise(request, topic_hit, policy.name, start, "embedding")

    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["guardrails"] = elapsed
    log.info(
        "guardrails_passed",
        org_id=org_id,
        request_id=request_id,
        pipeline_step="guardrails",
        embedding_source=source if db_result is not None else "in_process",
        elapsed_ms=round(elapsed, 2),
    )


def _set_state_and_raise(
    request: Request, category: str, policy_name: str, start: float, layer: str
) -> None:
    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["guardrails"] = elapsed
    request.state.guardrail_triggered = category
    request.state.guardrail_layer = layer

    log.warning(
        "guardrail_triggered",
        layer=layer,
        violation=category,
        policy=policy_name,
        org_id=getattr(request.state, "jwt_claims", {}).get("org_id", "unknown"),
        request_id=getattr(request.state, "request_id", ""),
        pipeline_step="guardrails",
    )

    raise HTTPException(
        status_code=451,
        detail={
            "error": "policy_violation",
            "reason": category,
            "policy": policy_name,
        },
    )
