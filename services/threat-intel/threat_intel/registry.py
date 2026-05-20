"""TI connector registry.

The ingestion orchestrator never imports connector classes directly. It
asks the registry for the set of connectors matching the requested
sources, capabilities, intel types, freshness tier, or required
credentials. Connectors self-register at module import time;
``threat_intel.connectors.__init__`` triggers the imports of the built-in
connector set.

Custom connectors follow the same pattern:

    from threat_intel.registry import default_registry
    class MyTIConnector(TIConnector): ...
    default_registry.register(MyTIConnector)
"""

from __future__ import annotations

from typing import Iterable

from threat_intel.base import TIConnector
from threat_intel.contracts import (
    ConnectorCapability,
    FreshnessTier,
    StixObjectType,
    TISource,
)
from threat_intel.errors import ConnectorNotFoundError, TIConfigError


class ConnectorRegistry:
    """In-process registry keyed by connector id."""

    def __init__(self) -> None:
        self._connectors: dict[str, type[TIConnector]] = {}

    # --- registration -----------------------------------------------------

    def register(self, connector_cls: type[TIConnector]) -> None:
        """Register a connector class.

        Idempotent for the same class object; raises ``TIConfigError`` if a
        *different* class tries to claim the same id.
        """
        connector_id = connector_cls.connector_id()
        existing = self._connectors.get(connector_id)
        if existing is not None and existing is not connector_cls:
            raise TIConfigError(
                f"connector id '{connector_id}' is already registered to {existing.__name__}",
                context={"existing": existing.__name__, "new": connector_cls.__name__},
            )
        self._connectors[connector_id] = connector_cls

    def unregister(self, connector_id: str) -> None:
        self._connectors.pop(connector_id, None)

    def clear(self) -> None:
        self._connectors.clear()

    # --- lookup -----------------------------------------------------------

    def get(self, connector_id: str) -> type[TIConnector]:
        try:
            return self._connectors[connector_id]
        except KeyError as exc:
            raise ConnectorNotFoundError(
                f"no connector registered with id '{connector_id}'",
                context={"connector_id": connector_id},
            ) from exc

    def all(self) -> list[type[TIConnector]]:
        return list(self._connectors.values())

    def by_source(self, source: TISource) -> list[type[TIConnector]]:
        return [cls for cls in self._connectors.values() if cls.metadata.source is source]

    def by_capability(self, capability: ConnectorCapability) -> list[type[TIConnector]]:
        return [
            cls for cls in self._connectors.values() if capability in cls.metadata.capabilities
        ]

    def by_object_type(self, stix_type: StixObjectType) -> list[type[TIConnector]]:
        return [
            cls
            for cls in self._connectors.values()
            if stix_type in cls.metadata.supported_object_types
        ]

    def by_freshness(self, tier: FreshnessTier) -> list[type[TIConnector]]:
        return [
            cls for cls in self._connectors.values() if cls.metadata.freshness.tier is tier
        ]

    def by_required_credential(
        self,
        *,
        mode: str | None = None,
        only_required: bool = False,
    ) -> list[type[TIConnector]]:
        """Find connectors that declare a particular credential mode.

        ``only_required=True`` filters out connectors where the credential is
        marked optional (the connector can degrade gracefully without it).
        """
        out: list[type[TIConnector]] = []
        for cls in self._connectors.values():
            for cred in cls.metadata.required_credentials:
                if mode is not None and cred.mode != mode:
                    continue
                if only_required and cred.optional:
                    continue
                out.append(cls)
                break
        return out

    def filter(
        self,
        *,
        sources: Iterable[TISource] | None = None,
        capabilities: Iterable[ConnectorCapability] | None = None,
        object_types: Iterable[StixObjectType] | None = None,
        freshness_tiers: Iterable[FreshnessTier] | None = None,
    ) -> list[type[TIConnector]]:
        """Compose multiple criteria with AND semantics.

        ``capabilities`` and ``object_types`` use *any-overlap* semantics: a
        connector matches if it declares at least one of the requested
        values.
        """
        sources_set = set(sources) if sources is not None else None
        capabilities_set = set(capabilities) if capabilities is not None else None
        object_types_set = set(object_types) if object_types is not None else None
        freshness_set = set(freshness_tiers) if freshness_tiers is not None else None

        out: list[type[TIConnector]] = []
        for cls in self._connectors.values():
            meta = cls.metadata
            if sources_set is not None and meta.source not in sources_set:
                continue
            if capabilities_set is not None and not capabilities_set.intersection(
                meta.capabilities
            ):
                continue
            if object_types_set is not None and not object_types_set.intersection(
                meta.supported_object_types
            ):
                continue
            if freshness_set is not None and meta.freshness.tier not in freshness_set:
                continue
            out.append(cls)
        return out


#: Module-level shared registry. Connectors self-register on import (see
#: ``threat_intel.connectors.__init__``). The orchestrator uses this
#: singleton by default; tests can pass a custom registry.
default_registry = ConnectorRegistry()
