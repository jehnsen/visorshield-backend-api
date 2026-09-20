from pydantic import model_validator
from pydantic_settings import BaseSettings
from typing import List, Literal, Optional

_INSECURE_JWT_DEFAULT = "change-me-in-production"


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://visorshield:visorshield@localhost/visorshield"
    REDIS_URL: str = "redis://localhost:6379"
    OPENAI_API_KEY: str = ""
    ANTHROPIC_API_KEY: str = ""
    JWT_SECRET: str = _INSECURE_JWT_DEFAULT
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 24
    DEFAULT_PROVIDER: Literal["openai", "anthropic"] = "openai"
    EMBEDDING_MODEL: str = "paraphrase-MiniLM-L6-v2"
    PGVECTOR_DIMENSIONS: int = 384
    EMBEDDING_CACHE_TTL_SECONDS: int = 300
    # Number of ivfflat lists to probe on the per-org guardrail ANN search.
    # Higher = better recall, slower. Migration 0002 builds the index with lists=10.
    IVFFLAT_PROBES: int = 5
    EMBEDDING_SIMILARITY_THRESHOLD: float = 0.72
    # Prompt-injection guardrail layer ("ignore previous instructions" family).
    GUARDRAIL_PROMPT_INJECTION_ENABLED: bool = True
    # Restore caller-supplied PII (masked out of the prompt) in the LLM response
    # so the client sees real names instead of [PERSON_1] tokens.
    PII_REHYDRATION_ENABLED: bool = True
    # Presidio/spaCy analysis is synchronous CPU work; it runs in a worker thread
    # so it never blocks the event loop. Bounds concurrent scans per process.
    PII_SCAN_MAX_THREADS: int = 4
    # Regions phonenumbers uses to validate numbers written without a country
    # code. Presidio's defaults omit PH, so "09171234567" and "(02) 8123-4567"
    # went undetected. PH first; the rest are Presidio's original defaults.
    PII_PHONE_REGIONS: List[str] = ["PH", "US", "UK", "DE", "FE", "IL", "IN", "CA", "BR"]
    # Webhook alerts
    WEBHOOK_URL: Optional[str] = None
    WEBHOOK_SECRET: Optional[str] = None
    # "all" fires on every incident; "keyword" / "embedding" fires only for that layer
    WEBHOOK_MIN_SEVERITY: str = "all"
    LOG_LEVEL: str = "INFO"
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    # Secure by default: if the DB is unreachable during the auth org/key-active
    # check, the request is BLOCKED rather than silently let through. Flipping
    # this to True is a deliberate availability-over-security trade-off for
    # non-production environments only — see validate_production_readiness.
    AUTH_FAIL_OPEN_ON_DB_ERROR: bool = False

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @model_validator(mode="after")
    def validate_production_readiness(self) -> "Settings":
        if self.ENVIRONMENT == "production":
            errors = []
            if self.JWT_SECRET == _INSECURE_JWT_DEFAULT:
                errors.append("JWT_SECRET must be changed from the default insecure value")
            if len(self.JWT_SECRET) < 32:
                errors.append("JWT_SECRET must be at least 32 characters")
            if not self.OPENAI_API_KEY and not self.ANTHROPIC_API_KEY:
                errors.append("At least one of OPENAI_API_KEY or ANTHROPIC_API_KEY must be set")
            if self.WEBHOOK_URL and not self.WEBHOOK_SECRET:
                errors.append("WEBHOOK_SECRET must be set when WEBHOOK_URL is configured")
            if self.AUTH_FAIL_OPEN_ON_DB_ERROR:
                errors.append("AUTH_FAIL_OPEN_ON_DB_ERROR must not be enabled in production")
            if errors:
                raise ValueError("Production configuration errors:\n" + "\n".join(f"  - {e}" for e in errors))
        return self


settings = Settings()
