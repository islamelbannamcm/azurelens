"""AlienVault OTX connector (STUB).

In Phase 2 this connector will pull from AlienVault OTX (Open Threat
Exchange) via its REST API. OTX is community-curated; we treat it as a
medium-trust source and apply per-tenant trust overrides.

NO OTX / HTTP calls happen here today.
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


class AlienVaultOTXConnector(TIConnector):
    """Pulls indicators and pulses from AlienVault OTX."""

    metadata = TIConnectorMetadata(
        id="alienvault_otx",
        name="AlienVault OTX",
        version="0.0.0",
        source=TISource.OTX,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.CAMPAIGNS,
            ConnectorCapability.ATTACK_PATTERNS_MITRE,
            ConnectorCapability.MALWARE_FAMILIES,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.CAMPAIGN,
            StixObjectType.ATTACK_PATTERN,
            StixObjectType.MALWARE,
            StixObjectType.RELATIONSHIP,
        ],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/otx-api-key",
                notes="OTX API key (header ``X-OTX-API-KEY``) stored in Key Vault.",
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "Community-curated TI from AlienVault OTX. Subscribed pulses + "
            "indicators, with MITRE technique tags where authors supplied them."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * GET ``/api/v1/pulses/subscribed?modified_since=<cursor>`` for
            incremental pulls.
          * For each pulse emit ``RawIntelItem(raw_format='otx_pulse')``.
          * Normalizer expands pulse indicators into ``NormalizedIndicator``
            with provenance back to the pulse id; pulse name + description
            become a Campaign-light object.
          * Apply default trust score ≤ 0.6; let tenants override.
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


default_registry.register(AlienVaultOTXConnector)
