"""/api/v1/reports — report generation & listing (placeholder).

Future work (Phase 1 → 3):
  * POST enqueues a render job to Service Bus ``report.generate.requested``.
  * Workers in ``services/reporting`` render PDF/PPTX/CSV/JSON.
  * Signed, expiring SAS URLs returned via ``blob_uri``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    Page,
    PageMeta,
    Report,
    ReportRequest,
    ReportStatus,
    ReportType,
)

router = APIRouter(prefix="/reports")

_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_REQUESTER = UUID("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
_NOW = datetime(2026, 5, 19, tzinfo=timezone.utc)


_MOCK_REPORT = Report(
    tenant_id=_TENANT_ID,
    id=UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
    type=ReportType.EXECUTIVE_PDF,
    status=ReportStatus.READY,
    title="Executive posture report — May 2026",
    parameters={"period": "monthly"},
    blob_uri="https://example.invalid/reports/placeholder.pdf",  # placeholder; replaced by signed SAS URL in Phase 1
    sha256="0" * 64,
    signed_by="kv-key-id-mock",
    requested_by=_REQUESTER,
    requested_at=_NOW,
    generated_at=_NOW,
    expires_at=None,
)


@router.get("", response_model=Page[Report], summary="List reports")
async def list_reports(
    type: ReportType | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[Report]:
    _ = (type, cursor, limit)
    return Page[Report](items=[_MOCK_REPORT], page=PageMeta(next_cursor=None, total_estimate=1))


@router.get("/{report_id}", response_model=Report, summary="Get one report")
async def get_report(report_id: UUID) -> Report:
    if report_id != _MOCK_REPORT.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="report_not_found")
    return _MOCK_REPORT


@router.post(
    "",
    response_model=Report,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request a report",
)
async def request_report(payload: ReportRequest) -> Report:
    # TODO(phase-1): authn + RBAC; enqueue to Service Bus 'report.generate.requested'.
    return Report(
        tenant_id=_TENANT_ID,
        id=uuid4(),
        type=payload.type,
        status=ReportStatus.QUEUED,
        title=payload.title,
        parameters=payload.parameters,
        blob_uri=None,
        sha256=None,
        signed_by=None,
        requested_by=_REQUESTER,
        requested_at=datetime.now(tz=timezone.utc),
        generated_at=None,
        expires_at=None,
    )
