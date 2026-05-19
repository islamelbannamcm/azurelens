"""Scan orchestrator (skeleton).

Demonstrates the future end-to-end flow but performs no real work today:

    receive ScanRequest
        └─► resolve enabled plugins via the registry (kinds → capabilities → providers)
              └─► build per-plugin ScanContext
                    └─► invoke plugin.scan(ctx) under timeout + error containment
                          └─► validate tenant-isolation invariant on every emitted record
                                └─► aggregate per-plugin ScanResult into ScanSummary

In Phase 1 the orchestrator will additionally:
  * fan out across Durable Functions / Container Apps Jobs,
  * acquire credentials through the platform's token provider (Managed Identity → OBO / app),
  * apply per-tenant + per-endpoint rate limiting,
  * stream ScanFinding events to Service Bus instead of returning in-process,
  * checkpoint partition progress for resumability,
  * emit OpenTelemetry spans + structured logs per plugin invocation,
  * persist raw evidence to ADLS Gen2 before normalizing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from uuid import UUID

from scanner.base import ScannerPlugin
from scanner.context import ScanContext
from scanner.contracts import (
    CloudProvider,
    ScanErrorEntry,
    ScanKind,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ScannerCapability,
)
from scanner.errors import (
    ScannerError,
    ScannerThrottledError,
    TenantIsolationError,
)
from scanner.registry import PluginRegistry, default_registry


# Map a ScanKind to the capability set we expect to satisfy it. The mapping is
# intentionally coarse — each plugin decides internally what it emits.
KIND_TO_CAPABILITIES: dict[ScanKind, frozenset[ScannerCapability]] = {
    ScanKind.AZURE: frozenset(
        {
            ScannerCapability.AZURE_INVENTORY,
            ScannerCapability.AZURE_NETWORK_POSTURE,
            ScannerCapability.AZURE_IDENTITY_POSTURE,
            ScannerCapability.AZURE_DATA_POSTURE,
            ScannerCapability.AZURE_POLICY_POSTURE,
        }
    ),
    ScanKind.M365: frozenset(
        {
            ScannerCapability.ENTRA_IDENTITY,
            ScannerCapability.ENTRA_CONDITIONAL_ACCESS,
            ScannerCapability.ENTRA_PRIVILEGED_ACCESS,
            ScannerCapability.ENTRA_RISK,
            ScannerCapability.ENTRA_APP_CONSENT,
            ScannerCapability.M365_COLLABORATION,
            ScannerCapability.M365_SECURE_SCORE,
        }
    ),
    ScanKind.INTUNE: frozenset(
        {
            ScannerCapability.INTUNE_DEVICE_INVENTORY,
            ScannerCapability.INTUNE_COMPLIANCE_POSTURE,
            ScannerCapability.INTUNE_CONFIG_POSTURE,
        }
    ),
    ScanKind.DEFENDER: frozenset(
        {
            ScannerCapability.DEFENDER_RECOMMENDATIONS,
            ScannerCapability.DEFENDER_SECURE_SCORE,
            ScannerCapability.DEFENDER_XDR_ALERTS,
        }
    ),
    ScanKind.SENTINEL: frozenset(
        {
            ScannerCapability.SENTINEL_ANALYTICS_POSTURE,
            ScannerCapability.SENTINEL_THREAT_INTEL_BRIDGE,
        }
    ),
    ScanKind.PURVIEW: frozenset(
        {
            ScannerCapability.PURVIEW_SENSITIVITY,
            ScannerCapability.PURVIEW_DLP,
            ScannerCapability.PURVIEW_RETENTION,
        }
    ),
}


class ScanOrchestrator:
    """Orchestrate one ``ScanRequest`` across the registered plugins."""

    def __init__(
        self,
        registry: PluginRegistry | None = None,
        *,
        per_plugin_timeout_seconds: float = 600.0,
    ) -> None:
        self._registry = registry or default_registry
        self._timeout = per_plugin_timeout_seconds

    # ----------------------------------------------------------------- public

    async def run(self, request: ScanRequest) -> ScanSummary:
        """Skeleton run loop. Sequentially invokes every resolved plugin.

        Phase 1 replaces sequential execution with bounded parallelism +
        Durable Functions fan-out. The sequential path here keeps the
        contract demonstration easy to read and trivial to unit-test.
        """
        started = _utcnow()
        resolved = self._resolve_plugins(request)
        if not resolved:
            return _empty_summary(request, started, status=ScanStatus.COMPLETED)

        per_plugin: dict[str, ScanResult] = {}
        for plugin_cls in resolved:
            ctx = self._build_context(request)
            per_plugin[plugin_cls.plugin_id()] = await self._invoke(plugin_cls, ctx)

        return self._aggregate(request, started, per_plugin)

    # ---------------------------------------------------------------- helpers

    def _resolve_plugins(self, request: ScanRequest) -> list[type[ScannerPlugin]]:
        """Pick the eligible plugin set for this request's kinds."""
        wanted_capabilities: set[ScannerCapability] = set()
        wanted_providers: set[CloudProvider] = set()

        for kind in request.kinds:
            if kind is ScanKind.FULL:
                # Full scan = every capability across every provider.
                for caps in KIND_TO_CAPABILITIES.values():
                    wanted_capabilities.update(caps)
                wanted_providers.update(CloudProvider)
            else:
                wanted_capabilities.update(KIND_TO_CAPABILITIES.get(kind, frozenset()))

        if not wanted_capabilities:
            return []

        return self._registry.filter(
            providers=wanted_providers or None,
            capabilities=wanted_capabilities,
        )

    def _build_context(self, request: ScanRequest) -> ScanContext:
        # TODO(phase-1): select CredentialMode based on the customer connector's
        # consent state (application vs delegated/OBO vs managed identity).
        return ScanContext(
            tenant_id=request.tenant_id,
            azure_tenant_id=request.azure_tenant_id,
            correlation_id=request.correlation_id,
            requested_at=request.requested_at,
            requested_by=request.requested_by,
        )

    async def _invoke(
        self,
        plugin_cls: type[ScannerPlugin],
        ctx: ScanContext,
    ) -> ScanResult:
        plugin = plugin_cls()
        plugin_id = plugin_cls.plugin_id()
        started = _utcnow()

        try:
            # TODO(phase-1): wrap call with retry policy, circuit breaker,
            # OpenTelemetry span, structured log scope, per-tenant rate limiter.
            result = await asyncio.wait_for(plugin.scan(ctx), timeout=self._timeout)
        except ScannerThrottledError as exc:
            return _error_result(plugin_id, ctx, started, ScanStatus.PARTIAL, exc, permanent=False)
        except asyncio.TimeoutError:
            return _error_result(
                plugin_id,
                ctx,
                started,
                ScanStatus.PARTIAL,
                ScannerError(
                    "plugin scan timed out", context={"timeout_seconds": self._timeout}
                ),
                permanent=False,
            )
        except ScannerError as exc:
            return _error_result(plugin_id, ctx, started, ScanStatus.FAILED, exc, permanent=True)
        except Exception as exc:  # noqa: BLE001 — last-resort containment
            return _error_result(
                plugin_id,
                ctx,
                started,
                ScanStatus.FAILED,
                ScannerError(f"uncaught plugin error: {type(exc).__name__}"),
                permanent=True,
            )

        # Tenant-isolation invariant (P0).
        self._validate_tenant_isolation(ctx.tenant_id, result)
        return result

    @staticmethod
    def _validate_tenant_isolation(expected_tenant_id: UUID, result: ScanResult) -> None:
        """Reject any plugin output bound to a different tenant.

        Cross-tenant emission is a P0 invariant violation: drop the offending
        records and raise; the caller converts to a ScanErrorEntry on the
        result. See docs/SCHEMA_DESIGN.md § 12.
        """
        if result.tenant_id != expected_tenant_id:
            raise TenantIsolationError(
                "plugin emitted ScanResult for a different tenant",
                context={
                    "expected": str(expected_tenant_id),
                    "actual": str(result.tenant_id),
                    "plugin_id": result.plugin_id,
                },
            )
        for asset in result.assets:
            if asset.tenant_id != expected_tenant_id:
                raise TenantIsolationError(
                    "plugin emitted asset for a different tenant",
                    context={"asset_id": asset.asset_id, "plugin_id": result.plugin_id},
                )
        for finding in result.findings:
            if finding.tenant_id != expected_tenant_id:
                raise TenantIsolationError(
                    "plugin emitted finding for a different tenant",
                    context={
                        "finding_type": finding.finding_type,
                        "plugin_id": result.plugin_id,
                    },
                )

    @staticmethod
    def _aggregate(
        request: ScanRequest,
        started: datetime,
        per_plugin: dict[str, ScanResult],
    ) -> ScanSummary:
        attempted = list(per_plugin.keys())
        succeeded = [pid for pid, r in per_plugin.items() if r.status is ScanStatus.COMPLETED]
        partial = [pid for pid, r in per_plugin.items() if r.status is ScanStatus.PARTIAL]
        failed = [pid for pid, r in per_plugin.items() if r.status is ScanStatus.FAILED]

        if failed and not (succeeded or partial):
            overall = ScanStatus.FAILED
        elif failed or partial:
            overall = ScanStatus.PARTIAL
        else:
            overall = ScanStatus.COMPLETED

        return ScanSummary(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            correlation_id=request.correlation_id,
            status=overall,
            started_at=started,
            ended_at=_utcnow(),
            plugins_attempted=attempted,
            plugins_succeeded=succeeded,
            plugins_partial=partial,
            plugins_failed=failed,
            total_assets=sum(len(r.assets) for r in per_plugin.values()),
            total_findings=sum(len(r.findings) for r in per_plugin.values()),
            errors=[e for r in per_plugin.values() for e in r.errors],
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _empty_summary(request: ScanRequest, started: datetime, *, status: ScanStatus) -> ScanSummary:
    return ScanSummary(
        request_id=request.request_id,
        tenant_id=request.tenant_id,
        correlation_id=request.correlation_id,
        status=status,
        started_at=started,
        ended_at=_utcnow(),
    )


def _error_result(
    plugin_id: str,
    ctx: ScanContext,
    started: datetime,
    status: ScanStatus,
    err: ScannerError,
    *,
    permanent: bool,
) -> ScanResult:
    return ScanResult(
        plugin_id=plugin_id,
        tenant_id=ctx.tenant_id,
        correlation_id=ctx.correlation_id,
        started_at=started,
        ended_at=_utcnow(),
        status=status,
        errors=[
            ScanErrorEntry(
                code=err.code,
                message=str(err),
                permanent=permanent,
                context=err.context,
            )
        ],
    )
