"""/api/v1/compliance — framework posture and per-control state (placeholder).

Future work (Phase 3):
  * Read per-tenant ``compliance_framework_posture`` rollups from SQL.
  * Per-control drill-down: which findings caused the non-compliant state.
  * Auditor mode: filter to evidence-bearing findings only.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    ComplianceControlState,
    ComplianceControlStatus,
    ComplianceFramework,
    ComplianceFrameworkPosture,
)

router = APIRouter(prefix="/compliance")


_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime(2026, 5, 19, tzinfo=timezone.utc)


@router.get(
    "/frameworks",
    response_model=list[ComplianceFramework],
    summary="List supported compliance frameworks",
)
async def list_frameworks() -> list[ComplianceFramework]:
    return list(ComplianceFramework)


@router.get(
    "/frameworks/{framework}/posture",
    response_model=ComplianceFrameworkPosture,
    summary="Per-tenant posture rollup for one framework",
)
async def framework_posture(
    framework: ComplianceFramework,
    version: str = Query(default="latest"),
) -> ComplianceFrameworkPosture:
    # TODO(phase-3): resolve real version when 'latest' is requested; load rollup from SQL.
    _ = version
    return ComplianceFrameworkPosture(
        tenant_id=_TENANT_ID,
        framework=framework,
        version="0.0.0-mock",
        total_controls=100,
        compliant=62,
        partially_compliant=18,
        non_compliant=14,
        not_applicable=4,
        insufficient_data=2,
        score=68.0,
        last_evaluated_at=_NOW,
    )


@router.get(
    "/frameworks/{framework}/controls",
    response_model=list[ComplianceControlState],
    summary="Per-control posture state for one framework",
)
async def framework_controls(
    framework: ComplianceFramework,
    control_status: ComplianceControlStatus | None = Query(default=None, alias="status"),
) -> list[ComplianceControlState]:
    _ = control_status
    return [
        ComplianceControlState(
            tenant_id=_TENANT_ID,
            framework=framework,
            version="0.0.0-mock",
            control_id="1.1.1",
            status=ComplianceControlStatus.NON_COMPLIANT,
            open_finding_count=3,
            evidence_finding_ids=[UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")],
            last_evaluated_at=_NOW,
        )
    ]


@router.get(
    "/frameworks/{framework}/controls/{control_id}",
    response_model=ComplianceControlState,
    summary="Per-tenant state for a single control",
)
async def control_state(framework: ComplianceFramework, control_id: str) -> ComplianceControlState:
    # TODO(phase-3): real lookup; 404 when the control is unknown for this version.
    if not control_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="control_not_found")
    return ComplianceControlState(
        tenant_id=_TENANT_ID,
        framework=framework,
        version="0.0.0-mock",
        control_id=control_id,
        status=ComplianceControlStatus.NON_COMPLIANT,
        open_finding_count=3,
        evidence_finding_ids=[UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")],
        last_evaluated_at=_NOW,
    )
