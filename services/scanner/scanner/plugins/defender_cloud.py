"""Defender for Cloud / Defender XDR scanner plugin (STUB).

In Phase 1 this plugin will pull Microsoft Defender for Cloud
recommendations, sub-assessments, regulatory-compliance state, and Secure
Score, plus a subset of Defender XDR alerts and incidents that bear on
posture (rather than active SOC investigation).

NO Defender API calls happen here today.
"""

from __future__ import annotations

from scanner.base import ScannerPlugin
from scanner.context import ScanContext
from scanner.contracts import (
    CloudProvider,
    PermissionGrantType,
    RequiredPermission,
    ScanResult,
    ScanStatus,
    ScannerCapability,
    ScannerMetadata,
)
from scanner.registry import default_registry


class DefenderCloudScanner(ScannerPlugin):
    """Defender for Cloud + Defender XDR posture scanner."""

    metadata = ScannerMetadata(
        id="defender_cloud",
        name="Microsoft Defender Scanner",
        version="0.0.0",
        provider=CloudProvider.DEFENDER_XDR,
        capabilities=[
            ScannerCapability.DEFENDER_RECOMMENDATIONS,
            ScannerCapability.DEFENDER_SECURE_SCORE,
            ScannerCapability.DEFENDER_XDR_ALERTS,
        ],
        supported_asset_kinds=[
            "defender.recommendation",
            "defender.secure_score_control",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.AZURE_RBAC,
                name="Security Reader",
                notes="Read Defender for Cloud recommendations and sub-assessments.",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.DEFENDER_API,
                name="SecurityAlert.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.DEFENDER_API,
                name="SecurityIncident.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.DEFENDER_API,
                name="AdvancedHunting.Read.All",
                optional=True,
                notes="Used for narrow hunting queries that correlate posture to seen activity.",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.DEFENDER_API,
                name="Machine.Read.All",
                optional=True,
                notes="Required when correlating Defender for Endpoint device inventory.",
            ),
        ],
        description=(
            "Reads Microsoft Defender for Cloud recommendations, sub-assessments, "
            "regulatory compliance state, Secure Score, and a posture-relevant "
            "slice of Defender XDR alerts / incidents."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1 / phase-4):
          * Pull Defender for Cloud recommendations + sub-assessments via the
            Security REST API (paged); compute deltas since the last scan.
          * Pull Microsoft Secure Score + controls via Graph
            ``/security/secureScores`` (history) and
            ``/security/secureScoreControlProfiles`` (definitions).
          * Pull Defender XDR alerts/incidents that bear on posture (filter
            tightly so we don't ingest live SOC investigation data here).
          * Emit ``ScanFinding`` per non-compliant recommendation, mapped to
            MCSB / CIS / NIST controls.
        """
        now = ScanContext.now()
        return ScanResult(
            plugin_id=self.metadata.id,
            tenant_id=ctx.tenant_id,
            correlation_id=ctx.correlation_id,
            started_at=now,
            ended_at=now,
            status=ScanStatus.COMPLETED,
        )


default_registry.register(DefenderCloudScanner)
