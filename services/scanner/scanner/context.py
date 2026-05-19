"""Per-scan runtime context.

ScanContext is the immutable, request-bound object passed into every plugin
invocation. It carries:

  * the AzureLens tenant identity (``tenant_id``) — partition key everywhere
  * the customer Entra ID tenant (``azure_tenant_id``) for token audience selection
  * a W3C ``traceparent`` correlation id propagated across logs / events
  * the credential strategy hint (the orchestrator owns the actual token provider)
  * an optional scan scope narrowing what the plugin should enumerate
  * an optional deadline (UTC) after which the plugin must stop

It is intentionally a small frozen dataclass (not Pydantic) so plugins are
cheap to invoke and trivial to mock in tests. The orchestrator validates
emitted records against ``ScanContext.tenant_id`` — see
``scanner.orchestrator.ScanOrchestrator._validate_tenant_isolation``.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID


class CredentialMode(str, Enum):
    """How the orchestrator should obtain a token for the customer tenant.

    Plugins NEVER read secrets directly. The orchestrator resolves tokens
    via Managed Identity → Entra ID workload identity federation and hands
    plugins an opaque token provider in Phase 1.
    """

    APPLICATION = "application"            # client credentials (app permissions)
    ON_BEHALF_OF = "on_behalf_of"          # delegated (OBO) for user-initiated reads
    MANAGED_IDENTITY = "managed_identity"  # in-Azure platform identity
    UNAUTHENTICATED = "unauthenticated"    # public TI sources only


@dataclass(frozen=True, slots=True)
class ScanScope:
    """Optional filters that narrow a single plugin invocation.

    All fields are tuples so the dataclass remains hashable.
    """

    subscription_ids: tuple[str, ...] = ()
    asset_kinds: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    user_object_ids: tuple[str, ...] = ()
    device_ids: tuple[str, ...] = ()
    # Free-form, plugin-specific overrides; not part of the equality hash.
    extra: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    def is_empty(self) -> bool:
        return not (
            self.subscription_ids
            or self.asset_kinds
            or self.asset_ids
            or self.user_object_ids
            or self.device_ids
            or self.extra
        )


@dataclass(frozen=True, slots=True)
class ScanContext:
    """Immutable per-request context handed to every plugin."""

    tenant_id: UUID
    azure_tenant_id: UUID
    correlation_id: str
    requested_at: datetime
    requested_by: UUID | None = None
    credential_mode: CredentialMode = CredentialMode.APPLICATION
    dry_run: bool = False
    scope: ScanScope = field(default_factory=ScanScope)
    deadline: datetime | None = None
    # Plugin-scoped, opaque cache key resolved by the orchestrator's token
    # provider; plugins must not interpret its contents.
    token_cache_key: str | None = None

    # ------------------------------------------------------------------ helpers

    def with_scope(self, scope: ScanScope) -> "ScanContext":
        """Return a copy with a new scope (rest of the context unchanged)."""
        return replace(self, scope=scope)

    def with_deadline(self, deadline: datetime) -> "ScanContext":
        """Return a copy with an updated deadline."""
        return replace(self, deadline=deadline)

    @staticmethod
    def now() -> datetime:
        """Current UTC time. Provided as a static helper so tests can monkeypatch."""
        return datetime.now(tz=timezone.utc)
