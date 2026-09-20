from app.models.policy import PolicyProfile, CustomRecognizer, CustomPattern

GOVTECH_POLICY = PolicyProfile(
    name="govtech",
    industry_type="govtech",
    pii_entities=[
        "PH_TIN",
        "PH_SSS",
        "PH_PHILSYS",
        "CREDIT_CARD",
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
    # Philippine recognizers. This is the single source of truth for these
    # formats — if BIR / SSS / PSA change them, update them here only.
    custom_recognizers=[
        CustomRecognizer(
            entity="PH_TIN",
            patterns=[
                # 9-digit TIN + 3-digit branch code (000 for head office)
                CustomPattern(name="tin_with_branch", regex=r"\b\d{3}-\d{3}-\d{3}-\d{3}\b", score=0.85),
                # 9-digit TIN written without the branch code
                CustomPattern(name="tin_no_branch", regex=r"\b\d{3}-\d{3}-\d{3}\b", score=0.6),
            ],
            context=["tin", "tax identification", "taxpayer", "bir"],
        ),
        CustomRecognizer(
            entity="PH_SSS",
            patterns=[CustomPattern(name="sss", regex=r"\b\d{2}-\d{7}-\d\b", score=0.85)],
            context=["sss", "social security"],
        ),
        CustomRecognizer(
            entity="PH_PHILSYS",
            patterns=[
                # PhilSys Card Number as printed: XXXX-XXXX-XXXX-XXXX
                CustomPattern(name="philsys_dashed", regex=r"\b\d{4}-\d{4}-\d{4}-\d{4}\b", score=0.75),
                # Bare 16 digits. Also the shape of a card number / order ID — a
                # Luhn-valid card is claimed by CREDIT_CARD (score 1.0) instead.
                CustomPattern(name="philsys_bare", regex=r"\b\d{16}\b", score=0.6),
            ],
            context=["philsys", "philid", "national id", "pcn", "psn"],
        ),
        # Filipino particle surnames: "Juan dela Cruz", "Ma. Cristina de los Santos".
        # spaCy's en_core_web_lg (English OntoNotes) often splits or misses these,
        # which after index-aware masking yields "[PERSON_1] dela [PERSON_2]".
        # Registered globally, so it also backs PERSON in the other profiles.
        CustomRecognizer(
            entity="PERSON",
            patterns=[
                CustomPattern(
                    name="ph_particle_surname",
                    regex=(
                        r"\b(?:Ma\.\s+)?[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+(?:\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+){0,2}"
                        r"\s+(?i:dela|delos|delas|del|de\s+la|de\s+los|de\s+las|de)"
                        r"\s+[A-ZÁÉÍÓÚÑ][a-záéíóúñ]+\b"
                    ),
                    # Above spaCy's 0.85 so the full name wins overlap resolution
                    score=0.9,
                )
            ],
            case_sensitive=True,
        ),
    ],
)
