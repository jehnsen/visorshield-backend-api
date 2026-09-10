import re
import time
import hashlib
import structlog
from typing import List, Dict, Tuple
from fastapi import Request, HTTPException
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from app.policies import get_policy

log = structlog.get_logger()

_analyzer: AnalyzerEngine | None = None


def _build_ph_recognizers() -> List[PatternRecognizer]:
    """Custom Philippine-specific entity recognizers."""
    tin = PatternRecognizer(
        supported_entity="PH_TIN",
        patterns=[Pattern("PH_TIN", r"\b\d{3}-\d{3}-\d{3}-\d{3}\b", 0.85)],
        name="PhilippineTINRecognizer",
    )
    sss = PatternRecognizer(
        supported_entity="PH_SSS",
        patterns=[Pattern("PH_SSS", r"\b\d{2}-\d{7}-\d{1}\b", 0.85)],
        name="PhilippineSSSRecognizer",
    )
    philsys = PatternRecognizer(
        supported_entity="PH_PHILSYS",
        patterns=[Pattern("PH_PHILSYS", r"\b\d{16}\b", 0.75)],
        name="PhilSysRecognizer",
    )
    return [tin, sss, philsys]


def get_analyzer() -> AnalyzerEngine:
    global _analyzer
    if _analyzer is None:
        registry = RecognizerRegistry()
        registry.load_predefined_recognizers()
        for rec in _build_ph_recognizers():
            registry.add_recognizer(rec)
        _analyzer = AnalyzerEngine(registry=registry)
    return _analyzer


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

    # Greedy non-overlapping selection: earliest start first, higher score wins
    # ties. Presidio can return overlapping spans; replacing them all would
    # corrupt offsets.
    ordered = sorted(results, key=lambda r: (r.start, -r.score, -(r.end - r.start)))
    selected = []
    last_end = -1
    for r in ordered:
        if r.start >= last_end:
            selected.append(r)
            last_end = r.end

    entity_counts: Dict[str, int] = {}
    placeholder_map: Dict[str, str] = {}
    spans: List[Tuple[int, int, str]] = []
    for r in sorted(selected, key=lambda r: r.start):
        etype = r.entity_type
        entity_counts[etype] = entity_counts.get(etype, 0) + 1
        placeholder = f"[{etype}_{entity_counts[etype]}]"
        placeholder_map[placeholder] = text[r.start:r.end]
        spans.append((r.start, r.end, placeholder))

    # Apply replacements right-to-left so earlier offsets remain valid.
    masked = text
    for start, end, placeholder in sorted(spans, key=lambda s: s[0], reverse=True):
        masked = masked[:start] + placeholder + masked[end:]

    detected_types = list({r.entity_type for r in selected})
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


def _apply_regex_patterns(text: str, patterns: Dict[str, str]) -> str:
    """Apply additional regex-based masking for custom patterns."""
    for label, pattern in patterns.items():
        text = re.sub(pattern, f"[{label}]", text)
    return text


async def pii_scan_request(request: Request) -> None:
    """
    Step 3 of the interceptor pipeline.
    Scans and redacts PII from all message content before forwarding to LLM.
    Fail-closed: blocks request on any Presidio exception.
    """
    start = time.monotonic()

    industry_type = request.headers.get("X-Industry-Type", "")
    policy = get_policy(industry_type)
    request_id = getattr(request.state, "request_id", "")
    org_id = getattr(request.state, "jwt_claims", {}).get("org_id", "unknown")

    entities = policy.pii_entities if policy else [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
    ]
    regex_patterns = policy.regex_patterns if policy else {}

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
                masked, detected, ph_map = _scan_text(msg.content, entities)
                masked = _apply_regex_patterns(masked, regex_patterns)
                msg.content = masked
                all_pii_detected.extend(detected)
                combined_map.update(ph_map)
            elif isinstance(msg.content, list):
                for part in msg.content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        masked, detected, ph_map = _scan_text(part["text"], entities)
                        masked = _apply_regex_patterns(masked, regex_patterns)
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
    policy = get_policy(industry_type)
    entities = policy.pii_entities if policy else [
        "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "US_SSN", "CREDIT_CARD",
    ]
    regex_patterns = policy.regex_patterns if policy else {}

    masked, detected, _ = _scan_text(text, entities)
    masked = _apply_regex_patterns(masked, regex_patterns)
    return masked, detected
