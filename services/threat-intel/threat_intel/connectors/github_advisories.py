"""GitHub Security Advisories (GHSA) connector (STUB).

In Phase 2 this connector will pull GHSA via the GitHub GraphQL API.
GHSA gives us per-ecosystem (npm, pip, NuGet, Maven, Go, Rust, ...)
advisories with CVSS, CVE links, affected version ranges, and patch
references — primary input for matching CVEs against software inventory
in the ``cve_in_inventory`` correlation pass.

NO GitHub / GraphQL calls happen here today.
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


class GitHubAdvisoriesConnector(TIConnector):
    """Pulls GitHub Security Advisories via GraphQL."""

    metadata = TIConnectorMetadata(
        id="github_advisories",
        name="GitHub Security Advisories (GHSA)",
        version="0.0.0",
        source=TISource.GHSA,
        capabilities=[
            ConnectorCapability.VULNERABILITIES_CVE,
        ],
        supported_object_types=[StixObjectType.VULNERABILITY],
        required_credentials=[
            RequiredCredential(
                mode="api_key",
                secret_ref="kv://platform-kv/ti/ghsa-pat",
                notes=(
                    "Fine-grained PAT with read-only access to advisories; stored "
                    "in Azure Key Vault. Higher rate limits than unauthenticated calls."
                ),
            ),
        ],
        freshness=FreshnessSLA(tier=FreshnessTier.SIX_HOURLY, max_staleness_minutes=360),
        description=(
            "GitHub Security Advisories — per-ecosystem advisories with CVSS, "
            "CVE links, affected version ranges, and patch info."
        ),
    )

    async def fetch(self, ctx: IngestionContext) -> IngestionResult:
        """Placeholder — no work performed.

        TODO(phase-2):
          * GraphQL query against ``securityAdvisories`` with ``updatedSince``
            cursor; paginate with ``cursor`` continuation.
          * Emit ``RawIntelItem(raw_format='ghsa_v1')``.
          * Normalizer produces ``NormalizedVulnerability``; ``affected_cpes``
            is filled from the advisory's package ecosystem + name + version
            range (translated to CPE 2.3 strings).
          * If the advisory has no associated CVE, the vulnerability is
            still ingested with id ``ghsa::<ghsa_id>`` so the dependency-
            scanner correlation pass can still match.
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


default_registry.register(GitHubAdvisoriesConnector)
