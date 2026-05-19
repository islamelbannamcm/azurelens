"""Microsoft 365 collaboration scanner plugin (STUB).

In Phase 1 this plugin will evaluate M365 collaboration posture: Exchange
Online mailboxes, SharePoint sites, Teams teams, OneDrive accounts, sharing
settings, anonymous-link policies, external collaboration controls, and the
Microsoft Secure Score for M365.

NO Microsoft Graph calls happen here today.
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


class M365SecurityScanner(ScannerPlugin):
    """Evaluates Microsoft 365 collaboration posture and Secure Score."""

    metadata = ScannerMetadata(
        id="m365_security",
        name="Microsoft 365 Security Scanner",
        version="0.0.0",
        provider=CloudProvider.M365,
        capabilities=[
            ScannerCapability.M365_COLLABORATION,
            ScannerCapability.M365_SECURE_SCORE,
        ],
        supported_asset_kinds=[
            "m365.mailbox",
            "m365.sharepoint_site",
            "m365.teams_team",
            "m365.onedrive",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Reports.Read.All",
                notes="Required to read Microsoft Secure Score and usage reports.",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="SecurityEvents.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="InformationProtectionPolicy.Read.All",
                optional=True,
                notes="Improves cross-link with Purview sensitivity-label findings.",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Files.Read.All",
                optional=True,
                notes=(
                    "Optional heuristic checks on SharePoint / OneDrive sharing; "
                    "off by default to minimize data exposure."
                ),
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Mail.ReadBasic.All",
                optional=True,
                notes="Optional phishing / DLP heuristics; off by default.",
            ),
        ],
        description=(
            "Evaluates Microsoft 365 collaboration posture across EXO, SPO, Teams, "
            "and OneDrive, plus the Microsoft Secure Score for M365."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1):
          * Pull Secure Score history via Graph ``/security/secureScores``.
          * Enumerate SharePoint sites / Teams / OneDrive accounts; check
            anonymous-link policies, external sharing scopes, guest access.
          * Emit ``ScanFinding`` per posture gap (e.g. anonymous sharing on,
            external collaboration unrestricted, missing DLP coverage).
          * Cross-link with Entra ID OAuth consent findings produced by the
            ``entra_identity`` plugin.
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


default_registry.register(M365SecurityScanner)
