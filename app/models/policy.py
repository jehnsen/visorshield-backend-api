from pydantic import BaseModel
from typing import List


class CustomPattern(BaseModel):
    name: str
    regex: str
    score: float


class CustomRecognizer(BaseModel):
    """
    A policy-owned regex entity, registered as a real Presidio PatternRecognizer.

    Going through Presidio (rather than a post-scan ``re.sub``) means matches get
    index-aware placeholders, land in ``placeholder_map`` for rehydration, show up
    in ``pii_detected`` for audit, and take part in overlap resolution and
    context enhancement like any built-in entity.
    """
    entity: str
    patterns: List[CustomPattern]
    # Nearby words that raise confidence (Presidio LemmaContextAwareEnhancer).
    context: List[str] = []
    # Presidio compiles patterns case-insensitively by default. Name patterns
    # rely on capitalisation, so they opt out.
    case_sensitive: bool = False


class PolicyProfile(BaseModel):
    name: str
    industry_type: str
    pii_entities: List[str]
    keyword_blocklist: List[str]
    prohibited_topics: List[str]
    custom_recognizers: List[CustomRecognizer] = []

    @property
    def scan_entities(self) -> List[str]:
        """Entities to request from the analyzer: built-ins plus this policy's custom ones."""
        extra = [r.entity for r in self.custom_recognizers if r.entity not in self.pii_entities]
        return list(self.pii_entities) + extra
