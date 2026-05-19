"""/api/v1/tenants — tenant onboarding, list, and detail (placeholder).

Returns deterministic mock data so the frontend and contract consumers have
something to integrate against. No persistence, no Entra ID admin-consent
exchange, no Azure RBAC assignments.

Future work (Phase 1):
  * Replace mocks with Azure SQL ``tenants`` reads/writes.
  * Implement admin-consent callback: validate state, persist consent, kick off
    a bootstrap scan via Service Bus ``scan.requested``.
  * Enforce RBAC: only ``GlobalAdmin`` may onboard or list tenants.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query, status

from app.models import (
    DataResidency,
    Page,
    PageMeta,
    Tenant,
    TenantStatus,
    TenantTier,
)
from app.models.tenant import TenantOnboardRequest, TenantSummary

router = APIRouter()


# Deterministic placeholder dataset (replaced by real persistence in Phase 1).
_MOCK_TENANT = Tenant(
    id=UUID("00000000-0000-0000-0000-000000000001"),
    azure_tenant_id=UUID("11111111-1111-1111-1111-111111111111"),
    display_name="Contoso Demo",
    primary_domain="contoso.onmicrosoft.com",
    tier=TenantTier.PRO,
    status=TenantStatus.ACTIVE,
    data_residency=DataResidency.EU,
    primary_contact=None,
    cmk_key_uri=None,
    created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    onboarded_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    offboarded_at=None,
)


@router.get(
    "",
    response_model=Page[TenantSummary],
    summary="List tenants visible to the caller",
)
async def list_tenants(
    cursor: str | None = Query(default=None, description="Opaque pagination cursor."),
    limit: int = Query(default=50, ge=1, le=500),
) -> Page[TenantSummary]:
    # TODO(phase-1): scope to tenants the caller has any role on; enforce GlobalAdmin filtering.
    _ = (cursor, limit)
    return Page[TenantSummary](
        items=[
            TenantSummary(
                id=_MOCK_TENANT.id,
                display_name=_MOCK_TENANT.display_name,
                tier=_MOCK_TENANT.tier,
                status=_MOCK_TENANT.status,
                data_residency=_MOCK_TENANT.data_residency,
            )
        ],
        page=PageMeta(next_cursor=None, total_estimate=1),
    )


@router.get(
    "/{tenant_id}",
    response_model=Tenant,
    summary="Get one tenant by id",
)
async def get_tenant(tenant_id: UUID) -> Tenant:
    # TODO(phase-1): tenant-context check; 403 on cross-tenant access.
    if tenant_id != _MOCK_TENANT.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="tenant_not_found")
    return _MOCK_TENANT


@router.post(
    "/onboard",
    response_model=Tenant,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Onboard a new tenant (admin-consent callback)",
)
async def onboard_tenant(payload: TenantOnboardRequest) -> Tenant:
    """Skeleton onboarding endpoint.

    In Phase 1 this becomes the admin-consent callback handler:
      1. Validate state/nonce from the consent redirect.
      2. Verify the platform multi-tenant app has the requested permissions.
      3. Persist tenant + initial connector records.
      4. Emit ``tenant.lifecycle`` event to start the bootstrap scan saga.
    For now: return a deterministic Tenant response built from the request.
    """
    now = datetime.now(tz=timezone.utc)
    return Tenant(
        id=uuid4(),
        azure_tenant_id=payload.azure_tenant_id,
        display_name=payload.display_name,
        primary_domain=payload.primary_domain,
        tier=payload.tier,
        status=TenantStatus.PROVISIONING,
        data_residency=payload.data_residency,
        primary_contact=payload.primary_contact,
        cmk_key_uri=None,
        created_at=now,
        updated_at=now,
        onboarded_at=None,
        offboarded_at=None,
    )
