"""Per-ingestion runtime context.

``IngestionContext`` is the immutable, request-bound object passed into
every connector invocation. It carries:

  * the destination tenant scope — almost always ``"shared"`` for global TI,
    or a customer ``tenant_id`` for tenant-private intel
  * the W3C ``traceparent`` correlation id
  * the upstream cursor (since-timestamp / opaque ETag / TAXII added_after)
  * the optional deadline (UTC) after which the connector must stop
  * batch size + page size hints
  * the credential cache key (the orchestrator owns the actual API-key /
    OAuth-token retrieval via Managed Identity → Key Vault)

It is a small frozen dataclass — not a Pydantic model — so connectors are
cheap to invoke and trivial to mock in tests. The orchestrator validates
every emitted intel object's ``tenant_id`` against the context's
destination scope.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID


# Sentinel string used as the partition value for the shared global TI corpus.
SHARED_CORPUS: str = "shared"


class CredentialMode(str, Enum):
    """How the orchestrator should obtain credentials for the upstream feed.

    Connectors NEVER read secrets directly. The orchestrator resolves them
    via Managed Identity → Azure Key Vault and hands the connector an
    opaque credential provider in Phase 2.
    """

    API_KEY = "api_key"            # bearer / header key in Key Vault
    OAUTH2_CLIENT = "oauth2_client"  # client credentials flow
    MUTUAL_TLS = "mutual_tls"        # client cert + key from Key Vault
    TAXII_BASIC = "taxii_basic"      # TAXII basic auth
    TAXII_OAUTH = "taxii_oauth"      # TAXII OAuth bearer
    AZURE_AD = "azure_ad"            # for Microsoft-owned feeds (Defender TI, Sentinel TI)
    NONE = "none"                    # open feed (CISA KEV, MITRE ATT&CK, NVD)


@dataclass(frozen=True, slots=True)
class FeedCursor:
    """Resumable cursor for an upstream feed.

    Feeds expose different cursor shapes (ISO timestamp, ETag, TAXII
    ``added_after`` / next-page token, opaque continuation). We carry all of
    them; connectors use whichever applies and ignore the rest.
    """

    since: datetime | None = None
    etag: str | None = None
    next_page_token: str | None = None
    # Free-form, connector-specific cursor state.
    extra: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


@dataclass(frozen=True, slots=True)
class IngestionContext:
    """Immutable per-call context handed to every connector."""

    # Destination scope. SHARED_CORPUS for global TI, a tenant UUID string
    # for tenant-private TI. Carried as ``str`` (not UUID) because of the
    # shared sentinel.
    destination_scope: str = SHARED_CORPUS

    correlation_id: str = ""
    requested_at: datetime = field(default_factory=lambda: datetime.now(tz=timezone.utc))

    credential_mode: CredentialMode = CredentialMode.NONE
    credential_cache_key: str | None = None

    cursor: FeedCursor = field(default_factory=FeedCursor)
    deadline: datetime | None = None

    # Soft hint to the connector. The connector may use it or ignore it.
    max_items: int | None = None
    page_size: int | None = None

    # Free-form per-call overrides (e.g. taxii collection id, MISP tag filter).
    overrides: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    # ------------------------------------------------------------------ helpers

    def with_cursor(self, cursor: FeedCursor) -> "IngestionContext":
        return replace(self, cursor=cursor)

    def with_deadline(self, deadline: datetime) -> "IngestionContext":
        return replace(self, deadline=deadline)

    def for_tenant(self, tenant_id: UUID) -> "IngestionContext":
        """Return a copy targeting a customer tenant's private corpus."""
        return replace(self, destination_scope=str(tenant_id))

    @property
    def is_shared(self) -> bool:
        return self.destination_scope == SHARED_CORPUS

    @staticmethod
    def now() -> datetime:
        return datetime.now(tz=timezone.utc)
