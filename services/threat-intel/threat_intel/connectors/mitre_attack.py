"""MITRE ATT&CK connector (STUB).

In Phase 2 this connector will pull the MITRE ATT&CK Enterprise + Mobile
STIX 2.1 bundles (open, public, no API key). It is the canonical source
of ``AttackPattern`` (technique) objects, ``Mitigation`` objects, and the
relationships between them.

ATT&CK is also the backbone of every framework crosswalk we produce —
findings, controls, and TI campaigns all reference ATT&CK technique ids
and the correlator uses them as a primary join key.

NO HTTP calls happen here today.
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
    StixObjectType,
    TIConnectorMetadata,
    TISource,
)
from threat_intel.registry import default_registry


class MitreAttackConnector(TIConnector):
    """Pulls the MITRE ATT&CK STIX 2.1 bundle (open feed)."""

    metadata = TIConnectorMetadata(
        id="mitre_attack",
        name="MITRE ATT&CK",
        version="0.0.0",
        source=TISource.MITRE_ATTACK,
        capabilities=[
            ConnectorCapability.ATTACK_PATTERNS_MITRE,
            ConnectorCapability.MITIGATIONS,
            ConnectorCapability.RELATIONSHIPS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.TOOLS,
            ConnectorCapability.THREAT_ACTORS,
        ],
        supported_object_types=[
            StixObjectType.ATTACK_PATTERN,
            StixObjectType.MITIGATION,
            StixObjectType.RELATIONSHIP,
            StixObjectType.MALWARE,
            StixObjectType.TOOL,
            StixObjectType.THREAT_ACTOR,
        ],
        required_credentials=[],  # public
        freshness=FreshnessSLA(tier=FreshnessTier.DAILY, max_staleness_minutes=1440),
        description=(
            "MITRE ATT&CK Enterprise + Mobile knowledge base — techniques, "
            "sub-techniques, tactics, mitigations, malware, tools, threat "
            "actors, and the relationships between them."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * GET the published STIX 2.1 bundle from the ATT&CK repository
            (large; cache aggressively with ETag).
          * For each SDO emit ``RawIntelItem(raw_format='stix2.1')``.
          * Normalizer handler:
              - splits AttackPattern into normalized ``technique_id``,
                ``tactics``, ``mitigations``, ``data_sources`` (used by
                the correlator's ``technique_to_finding`` pass).
              - preserves sub-technique parent links via Relationship rows.
          * Cloud matrix techniques are weighted higher by the risk engine.
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


default_registry.register(MitreAttackConnector)
