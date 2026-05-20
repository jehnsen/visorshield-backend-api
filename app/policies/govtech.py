from app.models.policy import PolicyProfile

GOVTECH_POLICY = PolicyProfile(
    name="govtech",
    industry_type="govtech",
    pii_entities=[
        "PH_TIN",
        "PH_SSS",
        "PH_PHILSYS",
        "PERSON",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "LOCATION",
        "DATE_TIME",
    ],
    keyword_blocklist=[
        "vote for",
        "campaign material",
        "political party endorsement",
        "election propaganda",
        "partisan",
        "candidate support",
        "anti-government",
        "overthrow",
    ],
    prohibited_topics=[
        "medical advice",
        "political campaigning",
        "partisan content",
        "election interference",
        "government overthrow",
        "classified information",
    ],
    regex_patterns={
        "PH_TIN": r"\b\d{3}-\d{3}-\d{3}-\d{3}\b",
        "PH_SSS": r"\b\d{2}-\d{7}-\d{1}\b",
        "PH_PHILSYS": r"\b\d{16}\b",
    },
)
