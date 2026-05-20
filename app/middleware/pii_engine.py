import re
import time
import hashlib
import structlog
from typing import List, Dict, Tuple
from fastapi import Request, HTTPException
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from app.policies import get_policy

log = structlog.get_logger()

_analyzer: AnalyzerEngine | None = None
_anonymizer: AnonymizerEngine | None = None


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


def get_anonymizer() -> AnonymizerEngine:
    global _anonymizer
    if _anonymizer is None:
        _anonymizer = AnonymizerEngine()
    return _anonymizer


def _scan_text(text: str, entities: List[str], language: str = "en") -> Tuple[str, List[str], Dict]:
    """
    Analyzes and anonymizes text. Returns (anonymized_text, entity_type_list, placeholder_map).
    entity_type_list contains only entity types (not values) for audit logging.
    """
    analyzer = get_analyzer()
    anonymizer = get_anonymizer()

    results = analyzer.analyze(text=text, entities=entities, language=language)
    if not results:
        return text, [], {}

    entity_counts: Dict[str, int] = {}
    operators: Dict[str, OperatorConfig] = {}

    for result in results:
        etype = result.entity_type
        entity_counts[etype] = entity_counts.get(etype, 0) + 1
        placeholder = f"[{etype}_{entity_counts[etype]}]"
        operators[etype] = OperatorConfig("replace", {"new_value": placeholder})

    anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
    detected_types = list({r.entity_type for r in results})

    # Build a reverse mapping for potential de-anonymization (not persisted to DB)
    placeholder_map = {}
    for result in sorted(results, key=lambda r: r.start):
        etype = result.entity_type
        original_value = text[result.start:result.end]
        n = entity_counts.get(etype, 1)
        placeholder = f"[{etype}_{n}]"
        placeholder_map[placeholder] = original_value

    return anonymized.text, detected_types, placeholder_map


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
