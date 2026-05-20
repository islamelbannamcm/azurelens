"""Microsoft Defender Threat Intelligence connector (STUB).

In Phase 2 this connector will pull from Microsoft Defender TI via the
Microsoft Graph ``/security/threatIntelligence`` endpoints (and, where
available, the dedicated MDTI APIs): indicators, articles, intel profiles,
host reputations, and the threat-actor / campaign graph Microsoft curates.

NO Microsoft Graph or MDTI calls happen here today.
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


class MicrosoftDefenderTIConnector(TIConnector):
    """Pulls Microsoft Defender Threat Intelligence via Microsoft Graph."""

    metadata = TIConnectorMetadata(
        id="microsoft_defender_ti",
        name="Microsoft Defender Threat Intelligence",
        version="0.0.0",
        source=TISource.DEFENDER_TI,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.CAMPAIGNS,
            ConnectorCapability.THREAT_ACTORS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.TOOLS,
            ConnectorCapability.ATTACK_PATTERNS_MITRE,
            ConnectorCapability.RELATIONSHIPS,
            ConnectorCapability.ON_DEMAND_LOOKUP,
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
                mode="azure_ad",
                secret_ref=None,
                notes=(
                    "Uses the platform multi-tenant app with Graph permission "
                    "ThreatIndicators.Read.All / TI.Read.All."
                ),
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "Microsoft-curated threat intelligence — indicators, articles, intel "
            "profiles, threat actors, campaigns, malware, tools, and ATT&CK mapping."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Acquire Graph token via the orchestrator's credential provider.
          * Page through ``/security/threatIntelligence/*`` endpoints
            using the cursor in ``ctx.cursor`` (last seen ``modifiedDateTime``
            and opaque continuation token).
          * Emit ``RawIntelItem`` with ``raw_format='vendor_json'`` for items
            that arrive in MDTI native format and ``raw_format='stix2.1'`` for
            STIX exports.
          * Honor 429 + Retry-After; back off with jitter.
          * Persist raw evidence (sanitized) to ADLS Gen2 before normalizing.
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


default_registry.register(MicrosoftDefenderTIConnector)
