"""AzureLens backend API entry point.

Skeleton only. Real middleware (auth, tenant resolution, rate limiting,
tracing, structured logging) will be wired in Phase 1.
See docs/ARCHITECTURE.md § 4.2 and docs/SECURITY_MODEL.md.
"""

from __future__ import annotations

from fastapi import FastAPI

from app.api.v1.router import api_router as v1_router
from app.core.config import get_settings


def create_app() -> FastAPI:
    """Application factory.

    A factory pattern keeps the app importable for tests without
    triggering side effects at import time.
    """
    settings = get_settings()

    app = FastAPI(
        title="AzureLens API",
        version="0.0.0",
        description=(
            "Backend API for the AzureLens platform. "
            "Skeleton — only the health endpoint is implemented."
        ),
        # OpenAPI is restricted in non-local environments via middleware in Phase 1.
        openapi_url="/openapi.json" if settings.is_local else None,
        docs_url="/docs" if settings.is_local else None,
        redoc_url=None,
    )

    # TODO(phase-1): add middleware in this order:
    #   1. RequestIdMiddleware            (W3C traceparent propagation)
    #   2. StructuredLoggingMiddleware    (structlog JSON logs)
    #   3. CORSMiddleware                 (locked-down allowlist)
    #   4. AuthMiddleware                 (Entra ID JWT validation)
    #   5. TenantContextMiddleware        (resolve + inject tenant_id)
    #   6. RBACMiddleware                 (role/scope enforcement per route)
    #   7. RateLimitMiddleware            (per-tenant token bucket)

    # TODO(phase-1): wire exception handlers that never leak internals
    # and always log with correlation_id.

    app.include_router(v1_router, prefix="/api/v1")

    return app


app = create_app()
