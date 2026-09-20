from app.models.policy import PolicyProfile, CustomRecognizer, CustomPattern

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
    custom_recognizers=[
        CustomRecognizer(
            entity="BAR_NUMBER",
            patterns=[CustomPattern(name="bar_number", regex=r"\bBar\s*#?\s*\d{4,8}\b", score=0.85)],
            context=["attorney", "roll", "ibp"],
        ),
    ],
)
