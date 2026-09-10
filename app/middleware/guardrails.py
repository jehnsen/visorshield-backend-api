import re
import time
import asyncio
import structlog
import numpy as np
from typing import List, Optional, Tuple, Dict
from fastapi import Request, HTTPException
from sentence_transformers import SentenceTransformer
from sqlalchemy import select, and_, text
from app.policies import get_policy
from app.config import settings

log = structlog.get_logger()

_embedding_model: SentenceTransformer | None = None

# Presence cache: key = "{org_id}:{policy_name}", value = (has_db_topics: bool, expiry_ts).
# We only cache *whether* an org has custom pgvector topics — the nearest-topic
# search itself runs in Postgres against the ivfflat index so it stays correct
# at thousands of topics.
_db_presence_cache: Dict[str, Tuple[bool, float]] = {}

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


async def _org_has_db_embeddings(org_id: str, policy_name: str) -> bool:
    """
    Whether this org has any custom pgvector guardrail topics for this policy.

    TTL-cached so the common case (no custom topics) costs one cheap EXISTS
    query every EMBEDDING_CACHE_TTL_SECONDS rather than a round-trip per request.
    On any DB error we return False and the caller falls back to the in-process
    default topics.
    """
    cache_key = f"{org_id}:{policy_name}"
    now = time.monotonic()

    cached = _db_presence_cache.get(cache_key)
    if cached is not None and now < cached[1]:
        return cached[0]

    has_rows = False
    try:
        from app.db.database import AsyncSessionLocal
        import uuid as _uuid

        async with AsyncSessionLocal() as session:
            found = await session.execute(
                text(
                    "SELECT 1 FROM policy_embeddings "
                    "WHERE org_id = :org_id AND policy_profile = :policy LIMIT 1"
                ),
                {"org_id": str(_uuid.UUID(org_id)), "policy": policy_name},
            )
            has_rows = found.first() is not None
    except Exception as exc:
        log.warning("db_embedding_presence_failed", error=str(exc), org_id=org_id, policy=policy_name)
        return False

    _db_presence_cache[cache_key] = (has_rows, now + settings.EMBEDDING_CACHE_TTL_SECONDS)
    return has_rows


async def _query_nearest_topic_db(
    org_id: str, policy_name: str, prompt_embedding: np.ndarray
) -> Optional[Tuple[str, float]]:
    """
    Nearest prohibited topic for this prompt, computed in Postgres against the
    ivfflat cosine index (idx_policy_embeddings_ivfflat). Returns (topic,
    cosine_similarity) for the closest row, or None on error / no rows.

    Using `ORDER BY embedding <=> :vec LIMIT 1` is what lets the planner use the
    ANN index; pulling every row into NumPy (the old approach) does not scale.
    """
    vec = np.asarray(prompt_embedding, dtype=np.float32).ravel()
    vec_literal = "[" + ",".join(f"{float(x):.8f}" for x in vec) + "]"

    try:
        from app.db.database import AsyncSessionLocal
        import uuid as _uuid

        probes = max(1, int(settings.IVFFLAT_PROBES))

        async with AsyncSessionLocal() as session:
            # Session-local knob: probe more lists for better recall. Inlined
            # (not bound) because Postgres SET does not take bind parameters;
            # the value is a coerced int from config, never user input.
            await session.execute(text(f"SET LOCAL ivfflat.probes = {probes}"))
            row = (
                await session.execute(
                    text(
                        "SELECT topic, 1 - (embedding <=> CAST(:vec AS vector)) AS similarity "
                        "FROM policy_embeddings "
                        "WHERE org_id = :org_id AND policy_profile = :policy "
                        "ORDER BY embedding <=> CAST(:vec AS vector) "
                        "LIMIT 1"
                    ),
                    {"vec": vec_literal, "org_id": str(_uuid.UUID(org_id)), "policy": policy_name},
                )
            ).first()

        if row is None:
            return None
        return row.topic, float(row.similarity)

    except Exception as exc:
        log.warning("db_embedding_query_failed", error=str(exc), org_id=org_id, policy=policy_name)
        return None


def invalidate_embedding_cache(org_id: str, policy_name: str) -> None:
    """Call this after upserting/deleting policy embeddings via the admin API."""
    cache_key = f"{org_id}:{policy_name}"
    _db_presence_cache.pop(cache_key, None)


def _check_keyword_blocklist(text: str, blocklist: List[str]) -> Optional[str]:
    text_lower = text.lower()
    for keyword in blocklist:
        if keyword.lower() in text_lower:
            return keyword
    return None


# ── Prompt-injection heuristics ──────────────────────────────────────────────
# Curated patterns for the "ignore previous instructions" family. Topic policy
# (keyword + embedding) does not cover instruction-override attacks, and an
# explicit prompt-injection control is a line item on healthcare / govtech RFPs.
# Deliberately conservative to keep false positives low on legitimate prompts.
_PROMPT_INJECTION_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("ignore_previous_instructions", re.compile(
        r"\b(?:ignore|disregard|forget|discard|skip)\b[^.\n]{0,40}?"
        r"\b(?:all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|earlier\s+|above\s+|preceding\s+|foregoing\s+)*"
        r"(?:instruction|prompt|direction|rule|guideline|context|message)s?\b", re.I)),
    ("override_system_prompt", re.compile(
        r"\b(?:override|bypass|circumvent|ignore|disable|turn\s+off|switch\s+off)\b[^.\n]{0,30}?"
        r"\b(?:system\s+prompt|system\s+message|safety|guardrail|content\s+filter|restriction|moderation|policy|policies)\b", re.I)),
    ("reveal_system_prompt", re.compile(
        r"\b(?:reveal|show|share|print|repeat|output|display|reprint|give\s+me|tell\s+me)\b[^.\n]{0,30}?"
        r"\b(?:your\s+)?(?:system\s+prompt|system\s+message|initial\s+instruction|original\s+instruction|"
        r"hidden\s+prompt|the\s+prompt\s+above|these\s+instructions)\b", re.I)),
    ("new_instructions_marker", re.compile(
        r"\b(?:new|updated|revised|real|actual|true)\s+(?:instruction|prompt|rule|task)s?\s*[:\-]", re.I)),
    ("role_override", re.compile(
        r"\byou\s+are\s+now\s+(?:a|an|the|no\s+longer|not)\b|"
        r"\bfrom\s+now\s+on[,]?\s+you\b|"
        r"\b(?:act|behave|respond|roleplay)\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+|an\s+)?"
        r"(?:unrestricted|unfiltered|uncensored|jailbroken|different)\b", re.I)),
    ("known_jailbreak_token", re.compile(
        r"\b(?:DAN|STAN|DUDE)\b|\bdeveloper\s+mode\b|\bdo\s+anything\s+now\b|\bjailbreak\b", re.I)),
    ("prompt_delimiter_injection", re.compile(
        r"</?(?:system|assistant|user|instructions?|prompt)\s*>|"
        r"\[/?(?:system|inst|instructions?|prompt)\]|"
        r"^\s*#{0,3}\s*system\s*:", re.I | re.M)),
]


def _check_prompt_injection(text: str) -> Optional[str]:
    """Return the name of the first matching prompt-injection pattern, or None."""
    for name, pattern in _PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            return name
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
    Step 4: Multi-layer compliance guardrail check.
    Layer 1 — keyword/regex blocklist (fast, synchronous).
    Layer 2 — prompt-injection heuristics ("ignore previous instructions" family).
    Layer 3 — embedding similarity. Per-org pgvector topics are searched in
              Postgres against the ivfflat index; otherwise the default
              in-process topic embeddings are used.
    Returns HTTP 451 on violation.
    """
    start = time.monotonic()

    industry_type = request.headers.get("X-Industry-Type", "")
    policy = get_policy(industry_type)
    request_id = getattr(request.state, "request_id", "")
    org_id = getattr(request.state, "jwt_claims", {}).get("org_id", "unknown")

    if not policy:
        # Should be unreachable: the proxy rejects unknown X-Industry-Type at the
        # top of the pipeline. Fail-closed if we ever get here anyway — never let
        # a request skip the guardrail check silently.
        request.state.pipeline_timing["guardrails"] = (time.monotonic() - start) * 1000
        log.error(
            "guardrails_no_policy",
            industry_type=industry_type,
            org_id=org_id,
            request_id=request_id,
            pipeline_step="guardrails",
        )
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_industry_type", "message": "Unknown or missing X-Industry-Type"},
        )

    body = getattr(request.state, "parsed_body", None)
    if body is None:
        return

    prompt_text = _extract_prompt_text(body)
    prompt_hash = getattr(request.state, "prompt_hash", "")

    # ── Layer 1: Keyword blocklist ──────────────────────────────────────────
    keyword_hit = _check_keyword_blocklist(prompt_text, policy.keyword_blocklist)
    if keyword_hit:
        _set_state_and_raise(request, keyword_hit, policy.name, start, "keyword")

    # ── Layer 2: Prompt-injection heuristics ───────────────────────────────
    if settings.GUARDRAIL_PROMPT_INJECTION_ENABLED:
        injection_hit = _check_prompt_injection(prompt_text)
        if injection_hit:
            _set_state_and_raise(
                request, f"prompt_injection:{injection_hit}", policy.name, start, "prompt_injection"
            )

    # ── Layer 3: Embedding similarity ──────────────────────────────────────
    model = get_embedding_model()
    prompt_embedding = model.encode([prompt_text], normalize_embeddings=True)[0]
    threshold = settings.EMBEDDING_SIMILARITY_THRESHOLD

    if await _org_has_db_embeddings(org_id, policy.name):
        # Nearest prohibited topic computed in Postgres via the ivfflat index.
        nearest = await _query_nearest_topic_db(org_id, policy.name, prompt_embedding)
        topic_hit = nearest[0] if (nearest and nearest[1] >= threshold) else None
        source = "pgvector_ivfflat"
    else:
        # Fall back to default in-process embeddings
        default_embs = _default_embeddings_cache.get(policy.name)
        if default_embs is None:
            # Warm up on-demand (first request before lifespan ran, e.g. in tests)
            default_embs = model.encode(policy.prohibited_topics, normalize_embeddings=True)
            _default_embeddings_cache[policy.name] = default_embs
        topic_hit = _check_embedding_similarity(
            prompt_embedding, default_embs, policy.prohibited_topics, threshold
        )
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
        embedding_source=source,
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
