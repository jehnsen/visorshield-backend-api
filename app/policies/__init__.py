from app.policies.healthcare import HEALTHCARE_POLICY
from app.policies.fintech import FINTECH_POLICY
from app.policies.govtech import GOVTECH_POLICY
from app.policies.legal_hr import LEGAL_HR_POLICY
from app.models.policy import PolicyProfile
from typing import Optional

POLICY_REGISTRY = {
    "healthcare": HEALTHCARE_POLICY,
    "fintech": FINTECH_POLICY,
    "govtech": GOVTECH_POLICY,
    "legal_hr": LEGAL_HR_POLICY,
}


def get_policy(industry_type: str) -> Optional[PolicyProfile]:
    return POLICY_REGISTRY.get(industry_type)
