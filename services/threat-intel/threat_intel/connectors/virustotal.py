"""VirusTotal connector (STUB, on-demand only).

In Phase 2 this connector will perform **on-demand** lookups against
VirusTotal — never bulk pull. VirusTotal is optional, commercial-tier,
and (critically) treated as a public source: customer-identifying data
must never be sent. Lookups use **hash-only** patterns; URLs / domains
are submitted only when the customer explicitly opts in per-tenant.

Privacy notes
-------------
* Default mode: **hash-only**. Domains / URLs are not submitted.
* Per-tenant override unlocks domain / URL lookups but the connector
  still strips any tenant-identifying query parameters before submission.
* No raw payload is persisted upstream; only the lookup *result* is
  cached in the shared corpus with a short TTL.

NO VirusTotal / HTTP calls happen here today.
"""

from __future__ import annotations

from threat_intel.base import TIConnector
from threat_intel.context import IngestionContext
from threat_intel.contracts import (
    ConnectorCapability,
    FreshnessSLA,
    FreshnessTier,
    IngestionResult,
    IngestionStatus,
    RequiredCredential,
    StixObjectType,
    TIConnectorMetadata,
    TISource,
)
from threat_intel.registry import default_registry


class VirusTotalConnector(TIConnector):
    """On-demand VirusTotal lookups (no bulk pull)."""

    metadata = TIConnectorMetadata(
        id="virustotal",
        name="VirusTotal (on-demand)",
        version="0.0.0",
        source=TISource.VIRUSTOTAL,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.ON_DEMAND_LOOKUP,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.MALWARE,
        ],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/virustotal-api-key",
                notes="Paid VT API key stored in Azure Key Vault.",
            ),
        ],
        # On-demand: scheduling is by lookup request, not by tier.
        freshness=FreshnessSLA(tier=FreshnessTier.ON_DEMAND, max_staleness_minutes=10080),
        description=(
            "On-demand enrichment against VirusTotal. Hash-only by default; "
            "URL / domain lookups gated by per-tenant opt-in. Never submits "
            "customer-identifying data."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Treat ``ctx.overrides['lookup_items']`` as the explicit work list;
            this connector does NOT do bulk sweeps.
          * Enforce hash-only by default; check per-tenant policy for URL /
            domain lookups; strip query parameters before submission.
          * Cache results in the shared corpus with a TTL (24-48h) — keyed by
            the canonical IOC, never by tenant id.
          * Respect VT API rate limits aggressively; budget per tenant per day.
        """
        now = IngestionContext.now()
        return IngestionResult(
            connector_id=self.metadata.id,
            source=self.metadata.source,
            destination_scope=ctx.destination_scope,
            correlation_id=ctx.correlation_id,
            started_at=now,
            ended_at=now,
            status=IngestionStatus.COMPLETED,
        )


default_registry.register(VirusTotalConnector)
