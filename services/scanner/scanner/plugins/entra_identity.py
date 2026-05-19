"""Entra ID identity scanner plugin (STUB).

In Phase 1 this plugin will use Microsoft Graph to evaluate Entra ID
identity posture: users, groups, directory roles, Conditional Access
policies, MFA strength, risky users / risk events, privileged role
assignments (PIM eligibility + activations), app registrations + service
principals + OAuth consent grants.

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


class EntraIdentityScanner(ScannerPlugin):
    """Evaluates Entra ID identity posture via Microsoft Graph."""

    metadata = ScannerMetadata(
        id="entra_identity",
        name="Entra ID Identity Scanner",
        version="0.0.0",
        provider=CloudProvider.ENTRA_ID,
        capabilities=[
            ScannerCapability.ENTRA_IDENTITY,
            ScannerCapability.ENTRA_CONDITIONAL_ACCESS,
            ScannerCapability.ENTRA_PRIVILEGED_ACCESS,
            ScannerCapability.ENTRA_RISK,
            ScannerCapability.ENTRA_APP_CONSENT,
        ],
        supported_asset_kinds=[
            "m365.user",
            "m365.group",
            "m365.directory_role",
            "m365.conditional_access_policy",
            "m365.application",
            "m365.service_principal",
            "m365.oauth_grant",
        ],
        required_permissions=[
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Directory.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="User.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Group.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Policy.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Policy.Read.ConditionalAccess",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="RoleManagement.Read.Directory",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="IdentityRiskyUser.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="IdentityRiskEvent.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="Application.Read.All",
            ),
            RequiredPermission(
                grant_type=PermissionGrantType.MS_GRAPH_APPLICATION,
                name="AuditLog.Read.All",
                optional=True,
                notes="Improves sign-in risk and stale-account analysis.",
            ),
        ],
        description=(
            "Evaluates Entra ID identity posture: users, groups, directory roles, "
            "Conditional Access, MFA strength, risky users/events, PIM, app "
            "registrations, service principals, and OAuth consent."
        ),
    )

    async def scan(self, ctx: ScanContext) -> ScanResult:
        """Placeholder — no work performed.

        TODO(phase-1):
          * Acquire Graph token via the orchestrator's token provider.
          * Page through ``/users``, ``/groups``, ``/directoryRoles``,
            ``/policies/conditionalAccessPolicies``,
            ``/identityProtection/riskyUsers``, ``/identityProtection/riskDetections``,
            ``/applications``, ``/servicePrincipals``, ``/oauth2PermissionGrants``
            via ``msgraph-sdk`` with ``$select`` / ``$top=999`` + delta queries.
          * Emit ``ScanAssetSnapshot`` per identity object and ``ScanFinding``
            per posture gap (missing MFA, legacy auth allowed, weak CA policies,
            permanent Global Admins, excessive privileged roles, risky users
            without remediation, broad OAuth consents).
          * Use ``ctx.scope.user_object_ids`` for targeted scans.
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


default_registry.register(EntraIdentityScanner)
