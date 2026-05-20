from app.models.policy import PolicyProfile

FINTECH_POLICY = PolicyProfile(
    name="fintech",
    industry_type="fintech",
    pii_entities=[
        "CREDIT_CARD",
        "IBAN_CODE",
        "SWIFT_BIC",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_BANK_NUMBER",
        "US_SSN",
        "PERSON",
    ],
    keyword_blocklist=[
        "guaranteed returns",
        "risk-free investment",
        "insider trading",
        "pump and dump",
        "money laundering",
        "tax evasion scheme",
        "bypass KYC",
        "AML circumvent",
    ],
    prohibited_topics=[
        "medical advice",
        "legal advice",
        "investment guarantees",
        "guaranteed profit",
        "risk-free returns",
        "securities manipulation",
    ],
    regex_patterns={
        "ROUTING_NUMBER": r"\b\d{9}\b",
        "CVV": r"\b\d{3,4}\b",
    },
)
