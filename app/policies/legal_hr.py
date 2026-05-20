from app.models.policy import PolicyProfile

LEGAL_HR_POLICY = PolicyProfile(
    name="legal_hr",
    industry_type="legal_hr",
    pii_entities=[
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "AGE",
        "NRP",
        "LOCATION",
        "DATE_TIME",
        "US_SSN",
    ],
    keyword_blocklist=[
        "must be young",
        "no older than",
        "preferred religion",
        "male only",
        "female only",
        "no minorities",
        "native speakers only",
        "no disabilities",
        "marital status required",
        "pregnancy status",
    ],
    prohibited_topics=[
        "discriminatory hiring language",
        "biased job descriptions",
        "age discrimination",
        "gender discrimination",
        "religious discrimination",
        "racial discrimination",
        "disability discrimination",
    ],
    regex_patterns={
        "BAR_NUMBER": r"\bBar\s*#?\s*\d{4,8}\b",
    },
)
