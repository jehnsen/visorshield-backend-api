from app.models.policy import PolicyProfile

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
    regex_patterns={
        "NPI": r"\b\d{10}\b",
        "DEA_NUMBER": r"\b[A-Z]{2}\d{7}\b",
    },
)
