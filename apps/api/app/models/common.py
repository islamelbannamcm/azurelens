"""Cross-cutting model primitives: tenant scoping, audit metadata, pagination.

These shapes are mixed into every major resource. They are deliberately small
and stable — changes here ripple across the whole API surface.
"""

from __future__ import annotations

from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Base config
# ---------------------------------------------------------------------------

_MODEL_CONFIG = ConfigDict(
    extra="forbid",          # reject unknown fields on input
    str_strip_whitespace=True,
    validate_assignment=True,
    populate_by_name=True,
    use_enum_values=False,
)


class AzureLensModel(BaseModel):
    """Base for every AzureLens schema; enforces strict, predictable behavior."""

    model_config = _MODEL_CONFIG


# ---------------------------------------------------------------------------
# Tenant scoping
# ---------------------------------------------------------------------------


class TenantScoped(AzureLensModel):
    """Mixin asserting that a record belongs to exactly one tenant.

    Multi-tenant invariant (see docs/SCHEMA_DESIGN.md § 12):
    every persisted record carries ``tenant_id`` and every query filters on it.
    """

    tenant_id: UUID = Field(
        ...,
        description="AzureLens tenant id (UUID). Required on every multi-tenant record.",
    )


# ---------------------------------------------------------------------------
# Audit metadata
# ---------------------------------------------------------------------------


class AuditMetadata(AzureLensModel):
    """Per-record audit shape attached to most domain objects."""

    created_at: datetime = Field(..., description="UTC timestamp when the record was created.")
    updated_at: datetime = Field(..., description="UTC timestamp when the record was last updated.")
    created_by: UUID | None = Field(
        default=None,
        description="Actor (user oid or system principal id) responsible for creation.",
    )
    updated_by: UUID | None = Field(
        default=None,
        description="Actor responsible for the last update.",
    )
    source: str | None = Field(
        default=None,
        description="Producing component, e.g. 'scanner-azure', 'compliance-engine'.",
    )
    schema_version: int = Field(default=1, ge=1, description="Model schema version.")


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------


class PageParams(AzureLensModel):
    """Request-side pagination parameters."""

    cursor: str | None = Field(
        default=None,
        description="Opaque cursor returned by a previous page; null for the first page.",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Maximum items to return.")


class PageMeta(AzureLensModel):
    """Response-side pagination metadata."""

    next_cursor: str | None = Field(
        default=None,
        description="Opaque cursor to fetch the next page; null when there is no further page.",
    )
    total_estimate: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Optional approximate total count. May be omitted for very large collections "
            "where exact counting is expensive."
        ),
    )


T = TypeVar("T")


class Page(AzureLensModel, Generic[T]):
    """Generic envelope for paginated list endpoints."""

    items: list[T] = Field(default_factory=list)
    page: PageMeta = Field(default_factory=PageMeta)
