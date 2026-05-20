from pydantic import BaseModel
from typing import List, Dict


class PolicyProfile(BaseModel):
    name: str
    industry_type: str
    pii_entities: List[str]
    keyword_blocklist: List[str]
    prohibited_topics: List[str]
    regex_patterns: Dict[str, str] = {}
