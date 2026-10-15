"""FastAPI application initialization, routing, lifespan, and global exception handlers."""

from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.config import get_settings
from app.database import async_engine, init_db
from app.routers import indexing, oauth, search_console
from app.schemas import ErrorDetail, ErrorResponse, HealthResponse

# Configure structured logging
settings = get_settings()
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("oauth_whiteboard")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: initializes database schemas on startup and cleans up engine on shutdown."""
    logger.info("Initializing database schemas...")
    await init_db()
    logger.info("Application startup completed successfully.")
    yield
    logger.info("Shutting down database engine...")
    await async_engine.dispose()
    logger.info("Application shutdown finished.")


app = FastAPI(
    title="OAuth Whiteboard — Google Search Console & Indexing API",
    description=(
        "Production-ready FastAPI backend demonstrating full Google OAuth 2.0 authorization, "
        "authenticated token encryption at rest, automatic token refresh, revocation, "
        "and on-demand URL indexing notifications with Google's Indexing API."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)


# Global Exception Handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Formats HTTPExceptions into a consistent ErrorResponse JSON envelope."""
    detail = exc.detail
    if isinstance(detail, dict):
        code = detail.get("code", "http_error")
        message = detail.get("message", "An HTTP error occurred.")
        details = detail.get("details", None)
    else:
        code = f"http_{exc.status_code}"
        message = str(detail)
        details = None

    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": code, "message": message, "details": details}},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Formats Pydantic validation errors without leaking sensitive internal variables."""
    formatted_errors = []
    for err in exc.errors():
        loc = " -> ".join(str(l) for l in err.get("loc", []))
        msg = err.get("msg", "Validation error")
        formatted_errors.append(f"{loc}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "error": {
                "code": "validation_error",
                "message": "Request payload or parameters failed validation.",
                "details": {"validation_errors": formatted_errors},
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catches unhandled errors, ensuring no stack traces or secrets leak in responses."""
    logger.exception(f"Unhandled server error on {request.method} {request.url.path}: {exc}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "internal_server_error",
                "message": "An unexpected error occurred while processing your request.",
            }
        },
    )


# Health & Readiness Endpoints
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Liveness check",
    description="Returns OK if the API server process is alive and receiving traffic.",
)
async def health_check():
    return HealthResponse(
        status="healthy",
        environment=settings.ENVIRONMENT,
        database="connected",
    )


@app.get(
    "/ready",
    response_model=HealthResponse,
    tags=["System"],
    summary="Readiness check",
    description="Validates database connectivity and service readiness.",
)
async def readiness_check():
    try:
        async with async_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_status = "ready"
    except Exception as exc:
        logger.error(f"Readiness database probe failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "database_unavailable", "message": "Database readiness probe failed."},
        )

    return HealthResponse(
        status="ready",
        environment=settings.ENVIRONMENT,
        database=db_status,
    )


# Register Feature Routers
app.include_router(oauth.router)
app.include_router(indexing.router)
app.include_router(search_console.router)
