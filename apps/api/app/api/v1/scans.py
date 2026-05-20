"""/api/v1/scans — scan history and trigger endpoints (demo mode).

Future work (Phase 1):
  * Replace demo_service with persistence; route POST through Service Bus
    ``scan.requested`` and propagate ``Idempotency-Key`` headers.
  * Stream live ``scan.partition.completed`` progress via WebSocket / SSE.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, status

from app.demo import demo_service
from app.demo.service import RecentScanSummary
from app.models import ScanRequest, ScanSummary
from app.models.scoring import ScanKind, ScanTriggerType

router = APIRouter()


class ScanTriggerRequest(ScanRequest):
    """Body for ``POST /scans``.

    Re-exports ``app.models.scoring.ScanRequest`` so the wire shape is the
    same as the canonical request used by the worker in Phase 1+.
    """


@router.get(
    "",
    response_model=list[ScanSummary],
    summary="List scan history (most recent first)",
)
async def list_scans() -> list[ScanSummary]:
    return demo_service.list_scans()


@router.get(
    "/recent",
    response_model=RecentScanSummary,
    summary="Most recent scan summary",
)
async def recent_scan() -> RecentScanSummary:
    return demo_service.recent_scan()


@router.get(
    "/{scan_id}",
    response_model=ScanSummary,
    summary="Get one scan",
)
async def get_scan(scan_id: UUID) -> ScanSummary:
    scan = demo_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan_not_found")
    return scan


@router.post(
    "",
    response_model=ScanSummary,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger a new scan (queued; no work performed in demo mode)",
)
async def trigger_scan(payload: ScanTriggerRequest | None = None) -> ScanSummary:
    if payload is None:
        payload = ScanTriggerRequest(
            request_id=uuid4(),
            tenant_id=demo_service.get_tenant().id,
            azure_tenant_id=demo_service.get_tenant().azure_tenant_id,
            kinds=[ScanKind.FULL],
            trigger_type=ScanTriggerType.ON_DEMAND,
            correlation_id="demo-correlation-id",
            requested_at=datetime.now(tz=timezone.utc),
        )
    # TODO(phase-1): publish to Service Bus 'scan.requested' and persist a row.
    return demo_service.trigger_scan(payload)
