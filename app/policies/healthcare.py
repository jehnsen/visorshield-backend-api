from app.models.policy import PolicyProfile, CustomRecognizer, CustomPattern

HEALTHCARE_POLICY = PolicyProfile(
    name="healthcare",
    industry_type="healthcare",
    pii_entities=[
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "MEDICAL_LICENSE",
        "US_SSN",
        "DATE_TIME",
        "US_DRIVER_LICENSE",
        "US_PASSPORT",
        "LOCATION",
    ],
    keyword_blocklist=[
        "prescribe",
        "diagnosis confirmed",
        "medical certificate",
        "clinical trial enroll",
        "off-label use",
        "dosage recommendation",
    ],
    prohibited_topics=[
        "legal advice",
        "financial advice",
        "prescribe medication",
        "guaranteed cure",
        "replace your doctor",
        "self-diagnose",
    ],
    custom_recognizers=[
        CustomRecognizer(
            entity="NPI",
            patterns=[CustomPattern(name="npi_10_digit", regex=r"\b\d{10}\b", score=0.4)],
            context=["npi", "provider", "national provider"],
        ),
        CustomRecognizer(
            entity="DEA_NUMBER",
            patterns=[CustomPattern(name="dea", regex=r"\b[A-Z]{2}\d{7}\b", score=0.6)],
            context=["dea", "registration"],
            case_sensitive=True,
        ),
    ],
)
