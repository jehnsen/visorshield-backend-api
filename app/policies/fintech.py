from app.models.policy import PolicyProfile, CustomRecognizer, CustomPattern

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
    custom_recognizers=[
        CustomRecognizer(
            entity="ROUTING_NUMBER",
            patterns=[CustomPattern(name="aba_routing", regex=r"\b\d{9}\b", score=0.4)],
            context=["routing", "aba", "rtn", "transit"],
        ),
        # Deliberately broad (matches any 3-4 digit number) to preserve existing
        # masking behaviour. Low score so any real entity at the same span wins.
        CustomRecognizer(
            entity="CVV",
            patterns=[CustomPattern(name="cvv", regex=r"\b\d{3,4}\b", score=0.3)],
            context=["cvv", "cvc", "cvv2", "security code"],
        ),
    ],
)
