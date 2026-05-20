"""Microsoft Sentinel Threat Intelligence connector (STUB).

In Phase 2 this connector will pull from the Sentinel-curated TI corpus
via TAXII 2.1 collections exposed by the customer's Log Analytics
workspace (or the Sentinel TI APIs). It also acts as a bridge for any
tenant-private indicators the customer maintains in Sentinel.

NO Sentinel / TAXII calls happen here today.
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


class SentinelTIConnector(TIConnector):
    """Pulls Microsoft Sentinel TI via TAXII 2.1 / Sentinel TI APIs."""

    metadata = TIConnectorMetadata(
        id="sentinel_ti",
        name="Microsoft Sentinel Threat Intelligence",
        version="0.0.0",
        source=TISource.SENTINEL_TI,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.CAMPAIGNS,
            ConnectorCapability.RELATIONSHIPS,
            ConnectorCapability.TAXII_COLLECTIONS,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.CAMPAIGN,
            StixObjectType.RELATIONSHIP,
        ],
        required_credentials=[
            RequiredCredential(
                mode="azure_ad",
                notes=(
                    "Uses the platform multi-tenant app with 'Microsoft Sentinel Reader' "
                    "on the customer workspace; the orchestrator may also use TAXII "
                    "OAuth where Sentinel exposes it directly."
                ),
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "Bridges Sentinel-curated TI (TAXII 2.1) plus tenant-private indicators "
            "maintained by the customer's SOC into the platform corpus."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Enumerate TAXII 2.1 collections exposed by the customer's
            Sentinel workspace.
          * Page indicators using ``added_after`` cursor stored in ``ctx.cursor``.
          * Tenant-private indicators (when the customer has them) MUST be
            written with ``destination_scope = str(tenant_id)`` — the
            orchestrator validates this and raises ``TIIsolationError`` on
            violation.
          * Emit STIX 2.1 envelopes as ``RawIntelItem(raw_format='stix2.1')``.
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


default_registry.register(SentinelTIConnector)
