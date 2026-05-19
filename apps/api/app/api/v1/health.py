"""Health endpoints.

Liveness: process is up (cheap, no dependencies).
Readiness: dependencies are reachable (added in Phase 1 once dependencies exist).

Health endpoints are intentionally unauthenticated. They MUST NOT expose
anything that could aid reconnaissance. Versions, hostnames, and dependency
detail belong in the internal /admin/diagnostics endpoint (Phase 1+, auth-gated).
"""

from __future__ import annotations

from fastapi import APIRouter, status
from pydantic import BaseModel

router = APIRouter()


class HealthResponse(BaseModel):
    status: str


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def health() -> HealthResponse:
    """Liveness probe — returns 200 if the process is serving requests."""
    return HealthResponse(status="ok")


# TODO(phase-1): readiness probe that checks:
#   - Key Vault reachable via Managed Identity
#   - SQL connection healthy
#   - Cosmos DB reachable
#   - Service Bus namespace reachable
# Return 503 with structured reason on failure (no internal detail leaked).
