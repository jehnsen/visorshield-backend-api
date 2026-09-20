import re
import time
import hashlib
import threading
import anyio
import structlog
from typing import List, Dict, Tuple
from fastapi import Request, HTTPException
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.predefined_recognizers import PhoneRecognizer
from app.config import settings
from app.models.policy import PolicyProfile
from app.policies import get_policy, POLICY_REGISTRY

log = structlog.get_logger()

_analyzer: AnalyzerEngine | None = None
_analyzer_lock = threading.Lock()
_scan_limiter: anyio.CapacityLimiter | None = None

# Used only when no policy resolves — unreachable via the proxy, which rejects
# unknown industry types before this step runs.
_FALLBACK_ENTITIES = ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD"]


def _build_policy_recognizers() -> List[PatternRecognizer]:
    """
    Build a Presidio PatternRecognizer for every policy's custom_recognizers.

    Registered globally; the per-request ``entities`` filter decides which ones
    apply, so e.g. PH_TIN only fires for profiles that ask for PH_TIN. The one
    deliberate exception is a PERSON-typed recognizer, which backs PERSON in
    every profile that requests it.
    """
    recognizers: List[PatternRecognizer] = []
    for policy_name, policy in POLICY_REGISTRY.items():
        for spec in policy.custom_recognizers:
            flags = re.DOTALL | re.MULTILINE
            if not spec.case_sensitive:
                flags |= re.IGNORECASE
            recognizers.append(
                PatternRecognizer(
                    supported_entity=spec.entity,
                    patterns=[Pattern(p.name, p.regex, p.score) for p in spec.patterns],
                    context=spec.context or None,
                    name=f"{policy_name}_{spec.entity}_recognizer",
                    global_regex_flags=flags,
                )
            )
    return recognizers


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        # Scans run in worker threads, so first use can race; build exactly once.
        with _analyzer_lock:
            if _analyzer is None:
                registry = RecognizerRegistry()
                registry.load_predefined_recognizers()
                # The default PhoneRecognizer validates against a region list that
                # omits PH, so local-format Philippine numbers were never detected.
                registry.remove_recognizer("PhoneRecognizer")
                registry.add_recognizer(
                    PhoneRecognizer(supported_regions=tuple(settings.PII_PHONE_REGIONS))
                )
                for rec in _build_policy_recognizers():
                    registry.add_recognizer(rec)
                _analyzer = AnalyzerEngine(registry=registry)
    return _analyzer


def _get_scan_limiter() -> anyio.CapacityLimiter:
    # Created lazily inside the running event loop.
    global _scan_limiter
    if _scan_limiter is None:
        _scan_limiter = anyio.CapacityLimiter(max(1, settings.PII_SCAN_MAX_THREADS))
    return _scan_limiter


def entities_for(policy: PolicyProfile | None) -> List[str]:
    """Entities to scan for under a policy, including its custom recognizers."""
    return policy.scan_entities if policy else list(_FALLBACK_ENTITIES)


async def scan_text_async(text: str, entities: List[str]) -> Tuple[str, List[str], Dict]:
    """
    ``_scan_text`` in a bounded worker thread.

    Presidio/spaCy analysis is synchronous CPU work. Run on the event loop it
    stalls every concurrent request on the worker — including ones just waiting
    on an upstream LLM response. Exceptions propagate unchanged, so callers keep
    their fail-closed handling.
    """
    return await anyio.to_thread.run_sync(
        _scan_text, text, entities, limiter=_get_scan_limiter()
    )


# Statistical NER recognizers. Their labels are broad guesses at a flat score
# (spaCy tags a bare 10-digit number DATE_TIME, or "Card 4111..." as PERSON), so
# a validated or pattern-based recognizer on the same text names it instead.
_NER_RECOGNIZERS = {"SpacyRecognizer", "TransformersRecognizer", "StanzaRecognizer"}


def _label_rank(r) -> Tuple[bool, float, int]:
    """Rank candidate labels for a merged region: specific recognizers, then score, then span length."""
    recognizer = (getattr(r, "recognition_metadata", None) or {}).get("recognizer_name")
    specific = recognizer not in _NER_RECOGNIZERS and r.score >= 0.3
    return (specific, r.score, r.end - r.start)


def _scan_text(text: str, entities: List[str], language: str = "en") -> Tuple[str, List[str], Dict]:
    """
    Analyzes and redacts text. Returns (masked_text, entity_type_list, placeholder_map).

    Every detected span gets its own index-aware placeholder (``[PERSON_1]``,
    ``[PERSON_2]``, …) so distinct entities of the same type stay distinguishable
    and ``placeholder_map`` is an accurate, complete reverse mapping for
    rehydration. entity_type_list contains only entity types (not values).
    """
    analyzer = get_analyzer()

    results = analyzer.analyze(text=text, entities=entities, language=language)
    if not results:
        return text, [], {}

    # Merge overlapping spans into single masked regions. Presidio often returns
    # several overlapping results for one piece of text; dropping any of them
    # would leave its non-overlapping characters unmasked. Merging guarantees
    # every character flagged by any recognizer stays masked (fail-closed).
    regions: List[list] = []  # [start, end, [results]]
    for r in sorted(results, key=lambda r: (r.start, r.end)):
        if regions and r.start < regions[-1][1]:
            regions[-1][1] = max(regions[-1][1], r.end)
            regions[-1][2].append(r)
        else:
            regions.append([r.start, r.end, [r]])

    entity_counts: Dict[str, int] = {}
    placeholder_map: Dict[str, str] = {}
    spans: List[Tuple[int, int, str]] = []
    labels: List[str] = []
    for start, end, members in regions:
        etype = max(members, key=_label_rank).entity_type
        labels.append(etype)
        entity_counts[etype] = entity_counts.get(etype, 0) + 1
        placeholder = f"[{etype}_{entity_counts[etype]}]"
        placeholder_map[placeholder] = text[start:end]
        spans.append((start, end, placeholder))

    # Apply replacements right-to-left so earlier offsets remain valid.
    masked = text
    for start, end, placeholder in reversed(spans):
        masked = masked[:start] + placeholder + masked[end:]

    detected_types = list(set(labels))
    return masked, detected_types, placeholder_map


def rehydrate_pii(text: str, placeholder_map: Dict[str, str]) -> Tuple[str, int]:
    """
    Restore caller-supplied PII values in an outbound LLM response.

    The prompt is masked before it reaches the model ("Juan dela Cruz" -> ``[PERSON_1]``);
    the model then echoes those placeholders back in its answer. This swaps them
    for the original values so the client gets a natural response instead of
    tokens — the single biggest UX differentiator vs. a plain proxy.

    Only values the caller themselves supplied (i.e. present in the request-scoped
    ``placeholder_map``) are restored. PII the model newly introduced is handled
    by the response scanner, which must run BEFORE this. ``placeholder_map`` is
    request-scoped and is never persisted or logged.

    Returns (rehydrated_text, number_of_substitutions).
    """
    if not text or not placeholder_map:
        return text, 0

    count = 0
    # Longest placeholders first so "[PERSON_1]" doesn't partially match "[PERSON_11]".
    for placeholder in sorted(placeholder_map, key=len, reverse=True):
        occurrences = text.count(placeholder)
        if occurrences:
            text = text.replace(placeholder, placeholder_map[placeholder])
            count += occurrences
    return text, count


async def pii_scan_request(request: Request) -> None:
    """
    Step 3 of the interceptor pipeline.
    Scans and redacts PII from all message content before forwarding to LLM.
    Fail-closed: blocks request on any Presidio exception.
    """
    start = time.monotonic()

    claims = getattr(request.state, "jwt_claims", {})
    # Sourced from the JWT claim (verified in auth_middleware to match the
    # X-Industry-Type header), never the raw header directly — the header is
    # client-controlled and picking the policy from it would let a caller
    # request a weaker entity list than their token was actually issued for.
    industry_type = claims.get("industry_type") or request.headers.get("X-Industry-Type", "")
    policy = get_policy(industry_type)
    request_id = getattr(request.state, "request_id", "")
    org_id = claims.get("org_id", "unknown")

    entities = entities_for(policy)

    body = getattr(request.state, "parsed_body", None)
    if body is None:
        return

    try:
        all_pii_detected = []
        full_original_text = ""

        for msg in body.messages:
            if isinstance(msg.content, str):
                full_original_text += msg.content + "\n"

        # Compute SHA-256 of original prompt BEFORE masking
        request.state.prompt_hash = hashlib.sha256(full_original_text.encode()).hexdigest()

        combined_map = {}
        for msg in body.messages:
            if isinstance(msg.content, str) and msg.content:
                masked, detected, ph_map = await scan_text_async(msg.content, entities)
                msg.content = masked
                all_pii_detected.extend(detected)
                combined_map.update(ph_map)
            elif isinstance(msg.content, list):
                for part in msg.content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        masked, detected, ph_map = await scan_text_async(part["text"], entities)
                        part["text"] = masked
                        all_pii_detected.extend(detected)
                        combined_map.update(ph_map)

        unique_pii = list(set(all_pii_detected))
        request.state.pii_detected = unique_pii
        request.state.pii_placeholder_map = combined_map

    except Exception as exc:
        log.error(
            "pii_scan_failed",
            error=str(exc),
            org_id=org_id,
            request_id=request_id,
            pipeline_step="pii_engine",
        )
        raise HTTPException(
            status_code=500,
            detail={"error": "pii_scan_failed", "message": "Request blocked for safety"},
        )

    elapsed = (time.monotonic() - start) * 1000
    request.state.pipeline_timing["pii_engine"] = elapsed

    log.info(
        "pii_scan_complete",
        org_id=org_id,
        request_id=request_id,
        pipeline_step="pii_engine",
        pii_detected=unique_pii,
        elapsed_ms=round(elapsed, 2),
    )


async def pii_scan_response(text: str, industry_type: str) -> Tuple[str, List[str]]:
    """
    Scans LLM response text for PII. Raises on any Presidio error so that the
    caller (response_scanner) can apply fail-closed behaviour (return placeholder).
    """
    masked, detected, _ = await scan_text_async(text, entities_for(get_policy(industry_type)))
    return masked, detected
