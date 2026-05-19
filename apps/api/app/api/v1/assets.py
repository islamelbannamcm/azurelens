"""/api/v1/assets — asset graph reads (placeholder).

Returns deterministic mock data. No Cosmos DB calls, no scanner ingestion.

Future work (Phase 1+):
  * Read from Cosmos containers ``assets`` and ``asset_edges`` partitioned by
    ``tenant_id``.
  * Support filters: provider, asset_kind, exposure, criticality, free-text.
  * Support graph traversal (``/assets/{id}/related``) bounded by depth.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    Asset,
    AssetKind,
    AssetSummary,
    CloudProvider,
    Criticality,
    ExposureLevel,
    Page,
    PageMeta,
)

router = APIRouter()


_TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
_NOW = datetime(2026, 5, 19, tzinfo=timezone.utc)

_MOCK_ASSET = Asset(
    tenant_id=_TENANT_ID,
    id="sha256:placeholder-asset-1",
    asset_uri="azure://subscriptions/00000000-0000-0000-0000-0000000000aa/resourceGroups/rg-demo/providers/Microsoft.Compute/virtualMachines/vm-demo",
    asset_kind=AssetKind.AZURE_VM,
    provider=CloudProvider.AZURE,
    subscription_id=UUID("00000000-0000-0000-0000-0000000000aa"),
    resource_group="rg-demo",
    location="westeurope",
    display_name="vm-demo",
    tags={"env": "demo"},
    criticality=Criticality.MODERATE,
    exposure=ExposureLevel.PUBLIC,
    owners=[],
    properties={
        "os": "Linux",
        "vm_size": "Standard_B2s",
        "open_ports": [22],
        # TODO(phase-1): full shape per docs/SCHEMA_DESIGN.md § 3.2.
    },
    relationships=[],
    discovered_at=_NOW,
    last_seen_at=_NOW,
    source="scanner-azure (mock)",
)


@router.get(
    "",
    response_model=Page[AssetSummary],
    summary="List assets",
)
async def list_assets(
    provider: CloudProvider | None = Query(default=None),
    asset_kind: AssetKind | None = Query(default=None),
    exposure: ExposureLevel | None = Query(default=None),
    criticality: Criticality | None = Query(default=None),
    cursor: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[AssetSummary]:
    # TODO(phase-1): tenant context resolved from JWT; query Cosmos with partition key.
    _ = (provider, asset_kind, exposure, criticality, cursor, limit)
    return Page[AssetSummary](
        items=[
            AssetSummary(
                id=_MOCK_ASSET.id,
                tenant_id=_MOCK_ASSET.tenant_id,
                asset_kind=_MOCK_ASSET.asset_kind,
                provider=_MOCK_ASSET.provider,
                display_name=_MOCK_ASSET.display_name,
                exposure=_MOCK_ASSET.exposure,
                criticality=_MOCK_ASSET.criticality,
                open_finding_count=2,
                highest_finding_severity="high",
            )
        ],
        page=PageMeta(next_cursor=None, total_estimate=1),
    )


@router.get(
    "/{asset_id}",
    response_model=Asset,
    summary="Get one asset",
)
async def get_asset(asset_id: str) -> Asset:
    # TODO(phase-1): enforce tenant-context filter; 404 outside tenant.
    if asset_id != _MOCK_ASSET.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="asset_not_found")
    return _MOCK_ASSET


# TODO(phase-1): GET /assets/{id}/related?depth=N — bounded graph traversal.
# TODO(phase-1): GET /assets/{id}/findings — convenience join into findings.
