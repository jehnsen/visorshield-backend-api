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

# The set of accepted X-Industry-Type header values. An unrecognized value must
# be rejected up front, never silently downgraded to a generic profile.
VALID_INDUSTRY_TYPES = frozenset(POLICY_REGISTRY.keys())


def get_policy(industry_type: str) -> Optional[PolicyProfile]:
    return POLICY_REGISTRY.get(industry_type)
