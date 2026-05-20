"""OpenCTI connector (STUB).

In Phase 2 this connector will pull from an OpenCTI instance via its
GraphQL API. OpenCTI is a STIX-native platform; payloads arrive already
STIX-shaped, which keeps the normalizer's work minimal.

NO OpenCTI / GraphQL calls happen here today.
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


class OpenCTIConnector(TIConnector):
    """Pulls TI from a configured OpenCTI instance (GraphQL)."""

    metadata = TIConnectorMetadata(
        id="opencti",
        name="OpenCTI",
        version="0.0.0",
        source=TISource.OPENCTI,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.CAMPAIGNS,
            ConnectorCapability.THREAT_ACTORS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.TOOLS,
            ConnectorCapability.ATTACK_PATTERNS_MITRE,
            ConnectorCapability.RELATIONSHIPS,
            ConnectorCapability.SECTOR_INTEL,
            ConnectorCapability.GEOGRAPHIC_INTEL,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.CAMPAIGN,
            StixObjectType.THREAT_ACTOR,
            StixObjectType.MALWARE,
            StixObjectType.TOOL,
            StixObjectType.ATTACK_PATTERN,
            StixObjectType.RELATIONSHIP,
        ],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/opencti-token",
                notes="OpenCTI bearer token stored in Azure Key Vault.",
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "Pulls TI from an OpenCTI instance via GraphQL. STIX-native; "
            "rich relationship graph between indicators, campaigns, actors, "
            "malware, tools, techniques."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Use the OpenCTI Python client (lazy-imported) with the bearer
            token resolved by the orchestrator.
          * Paginate via the platform's cursor; OpenCTI exposes
            ``createdAt`` / ``updatedAt`` filters and connection cursors.
          * Emit ``RawIntelItem(raw_format='stix2.1')`` — OpenCTI exports
            STIX directly.
          * Be defensive about large relationship graphs; stream rather
            than buffer.
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


default_registry.register(OpenCTIConnector)
