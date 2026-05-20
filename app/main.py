import uuid
import structlog
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from app.config import settings
from app.routers import proxy, audit, admin
from app.db.database import check_db_health
from app.middleware.rate_limit import get_redis
from app.middleware.pii_engine import get_analyzer
from app.middleware.guardrails import get_embedding_model, warmup_embeddings

# Configure structlog
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(
        getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)
    ),
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger()


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("visorshield_starting", environment=settings.ENVIRONMENT)

    # Warm up Presidio NLP pipeline
    try:
        get_analyzer()
        log.info("presidio_initialized")
    except Exception as exc:
        log.error("presidio_init_failed", error=str(exc))

    # Warm up sentence-transformers + pre-compute all default policy embeddings.
    # This runs in a thread because SentenceTransformer.encode is CPU-bound.
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, warmup_embeddings)
        log.info("embeddings_warmed")
    except Exception as exc:
        log.error("embedding_warmup_failed", error=str(exc))

    yield
    log.info("visorshield_shutdown")


app = FastAPI(
    title="VisorShield",
    description="Universal AI Governance Proxy",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id

    # Ensure pipeline_timing always exists
    if not hasattr(request.state, "pipeline_timing"):
        request.state.pipeline_timing = {}

    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(
        request_id=request_id,
        path=request.url.path,
        method=request.method,
    )

    response = await call_next(request)
    response.headers["X-VisorShield-Request-ID"] = request_id
    return response


app.include_router(proxy.router)
app.include_router(audit.router)
app.include_router(admin.router)


@app.get("/health", tags=["health"])
async def health_check():
    db_ok = await check_db_health()

    redis_ok = False
    try:
        redis = get_redis()
        await redis.ping()
        redis_ok = True
    except Exception:
        pass

    presidio_ok = False
    try:
        get_analyzer()
        presidio_ok = True
    except Exception:
        pass

    embeddings_ok = False
    try:
        get_embedding_model()
        embeddings_ok = True
    except Exception:
        pass

    status = "healthy" if (db_ok and redis_ok and presidio_ok and embeddings_ok) else "degraded"

    return JSONResponse(
        status_code=200 if status == "healthy" else 503,
        content={
            "status": status,
            "version": "1.0.0",
            "services": {
                "database": "ok" if db_ok else "error",
                "redis": "ok" if redis_ok else "error",
                "presidio": "ok" if presidio_ok else "error",
                "embeddings": "ok" if embeddings_ok else "error",
            },
        },
    )
