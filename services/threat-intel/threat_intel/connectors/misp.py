"""MISP connector (STUB).

In Phase 2 this connector will pull events / attributes / galaxies from
a customer-supplied MISP instance via PyMISP or the MISP REST API. MISP
is a high-signal community-curated TI source — events carry rich tags,
galaxies (including MITRE galaxies), and per-attribute confidence.

NO MISP / PyMISP calls happen here today.
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


class MispConnector(TIConnector):
    """Pulls events from a configured MISP instance."""

    metadata = TIConnectorMetadata(
        id="misp",
        name="MISP",
        version="0.0.0",
        source=TISource.MISP,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.CAMPAIGNS,
            ConnectorCapability.THREAT_ACTORS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.ATTACK_PATTERNS_MITRE,
            ConnectorCapability.RELATIONSHIPS,
            ConnectorCapability.SECTOR_INTEL,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.CAMPAIGN,
            StixObjectType.THREAT_ACTOR,
            StixObjectType.MALWARE,
            StixObjectType.ATTACK_PATTERN,
            StixObjectType.RELATIONSHIP,
        ],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/misp-api-key",
                notes="Per-tenant MISP API key stored in Azure Key Vault.",
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "Pulls events from a MISP instance — attributes, galaxies (incl. "
            "MITRE), tags, sightings; rich community-curated TI."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Use ``pymisp.PyMISP`` (lazy-imported) authenticated with the
            API key resolved by the orchestrator's credential provider.
          * Filter events by ``timestamp >= ctx.cursor.since`` and tag /
            galaxy allowlists (per-tenant overrides).
          * Emit ``RawIntelItem(raw_format='misp_event')`` for each event;
            normalizer expands attributes into indicators, galaxies into
            ATT&CK / malware references, and tags into labels.
          * Honor rate limits configured at the MISP server.
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


default_registry.register(MispConnector)
