"""AzureLens backend API entry point.

Demo mode (Phase 7) wires CORS for local frontend development so
``apps/frontend`` running on ``http://localhost:3000`` can reach this API
on ``http://localhost:8000``. The CORS allowlist is intentionally
**local-only** and gated on ``Settings.is_local`` — production deployments
add no permissive CORS rules. See ``docs/SECURITY_MODEL.md``.

Real middleware (auth, tenant resolution, rate limiting, tracing,
structured logging) is wired in Phase 1; the order is documented inline.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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
            "Backend API for the AzureLens platform. Demo mode in Phase 7: "
            "the v1 surface returns deterministic data for the 'Contoso Demo' "
            "tenant. See docs/DEMO_MODE.md."
        ),
        # OpenAPI is restricted in non-local environments via middleware in Phase 1.
        openapi_url="/openapi.json" if settings.is_local else None,
        docs_url="/docs" if settings.is_local else None,
        redoc_url=None,
    )

    # --- CORS (LOCAL DEVELOPMENT ONLY) --------------------------------------
    # Phase 7 enables CORS so the Next.js frontend (http://localhost:3000)
    # can call this API. The allowlist is GATED on Settings.is_local so this
    # never activates in dev / staging / prod environments. Phase 1 replaces
    # this with an APIM-managed CORS policy + explicit per-environment
    # allowlist driven by App Configuration (see docs/SECURITY_MODEL.md § 7).
    if settings.is_local:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ],
            allow_credentials=False,  # local dev only; no cookies leaving the API
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "traceparent"],
            max_age=600,
        )

    # TODO(phase-1): add middleware in this order, replacing the CORS block above:
    #   1. RequestIdMiddleware            (W3C traceparent propagation)
    #   2. StructuredLoggingMiddleware    (structlog JSON logs, PII redaction)
    #   3. SecurityHeadersMiddleware      (HSTS, CSP, X-Content-Type-Options, etc.)
    #   4. APIM-managed CORS              (no permissive rules here; APIM owns it)
    #   5. AuthMiddleware                 (Entra ID JWT validation, JWKS w/ rotation)
    #   6. TenantContextMiddleware        (resolve + inject tenant_id; reject mismatches)
    #   7. RBACMiddleware                 (role/scope enforcement per route)
    #   8. RateLimitMiddleware            (per-tenant token bucket)
    #   9. IdempotencyMiddleware          (Idempotency-Key cache for state-changing POSTs)

    # TODO(phase-1): wire exception handlers that always log with correlation_id
    # and NEVER leak stack traces, internal hostnames, or upstream error bodies.

    app.include_router(v1_router, prefix="/api/v1")

    return app


app = create_app()
