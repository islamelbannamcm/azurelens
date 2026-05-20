"""abuse.ch connector (STUB).

In Phase 2 this connector will pull from the abuse.ch ecosystem:
URLhaus, MalwareBazaar, and ThreatFox. abuse.ch is high-signal for
commodity malware C2 / payload / IOC data and is one of the cheapest
sources to keep fresh.

NO abuse.ch / HTTP calls happen here today.
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


class AbuseChConnector(TIConnector):
    """Pulls from URLhaus / MalwareBazaar / ThreatFox (abuse.ch)."""

    metadata = TIConnectorMetadata(
        id="abuse_ch",
        name="abuse.ch (URLhaus / MalwareBazaar / ThreatFox)",
        version="0.0.0",
        source=TISource.ABUSE_CH,
        capabilities=[
            ConnectorCapability.INDICATORS,
            ConnectorCapability.MALWARE_FAMILIES,
            ConnectorCapability.RELATIONSHIPS,
        ],
        supported_object_types=[
            StixObjectType.INDICATOR,
            StixObjectType.MALWARE,
            StixObjectType.RELATIONSHIP,
        ],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/abuse-ch-auth-key",
                optional=True,
                notes=(
                    "abuse.ch issues optional Auth-Keys for higher rate limits. "
                    "Public endpoints work without one at lower rates."
                ),
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.HOURLY, max_staleness_minutes=90),
        description=(
            "abuse.ch URLhaus (malicious URLs), MalwareBazaar (samples + hashes), "
            "and ThreatFox (IOCs tagged by malware family). High-volume commodity "
            "threat data."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * Sub-modules per service (URLhaus / MalwareBazaar / ThreatFox)
            with their own pagination and cursor semantics.
          * GET recent additions since ``ctx.cursor.since``; honor any
            ``Auth-Key`` configured.
          * Emit ``RawIntelItem(raw_format='abuse_ch_v1')`` with a
            ``service`` field in metadata.
          * Normalizer expands rows into ``NormalizedIndicator`` (URLs,
            hashes, domains) and links them to a ``NormalizedMalware``
            object via Relationship when the row carries a family tag.
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


default_registry.register(AbuseChConnector)
