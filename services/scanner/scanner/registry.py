"""Plugin registry.

The orchestrator never imports plugin classes directly. It asks the registry
for the set of plugins matching a request's kinds, capabilities, asset types,
and required permissions. Plugins self-register at module import time;
``scanner.plugins.__init__`` triggers the imports of the built-in plugin set.

Custom plugins follow the same convention:

    from scanner.registry import default_registry
    class MyCustomScanner(ScannerPlugin): ...
    default_registry.register(MyCustomScanner)

Lookups are O(N) over a small N (≤ a few dozen plugins). When N grows, the
registry can be indexed without changing the public API.
"""

from __future__ import annotations

from typing import Iterable

from scanner.base import ScannerPlugin
from scanner.contracts import (
    CloudProvider,
    PermissionGrantType,
    ScannerCapability,
)
from scanner.errors import PluginNotFoundError, ScannerConfigError


class PluginRegistry:
    """In-process registry keyed by plugin id."""

    def __init__(self) -> None:
        self._plugins: dict[str, type[ScannerPlugin]] = {}

    # --- registration -----------------------------------------------------

    def register(self, plugin_cls: type[ScannerPlugin]) -> None:
        """Register a plugin class.

        Idempotent for the same class object; raises ``ScannerConfigError``
        if a different class tries to claim the same id.
        """
        plugin_id = plugin_cls.plugin_id()
        existing = self._plugins.get(plugin_id)
        if existing is not None and existing is not plugin_cls:
            raise ScannerConfigError(
                f"plugin id '{plugin_id}' is already registered to {existing.__name__}",
                context={"existing": existing.__name__, "new": plugin_cls.__name__},
            )
        self._plugins[plugin_id] = plugin_cls

    def unregister(self, plugin_id: str) -> None:
        self._plugins.pop(plugin_id, None)

    def clear(self) -> None:
        self._plugins.clear()

    # --- lookup -----------------------------------------------------------

    def get(self, plugin_id: str) -> type[ScannerPlugin]:
        try:
            return self._plugins[plugin_id]
        except KeyError as exc:
            raise PluginNotFoundError(
                f"no plugin registered with id '{plugin_id}'",
                context={"plugin_id": plugin_id},
            ) from exc

    def all(self) -> list[type[ScannerPlugin]]:
        return list(self._plugins.values())

    def by_provider(self, provider: CloudProvider) -> list[type[ScannerPlugin]]:
        return [cls for cls in self._plugins.values() if cls.metadata.provider is provider]

    def by_capability(self, capability: ScannerCapability) -> list[type[ScannerPlugin]]:
        return [cls for cls in self._plugins.values() if capability in cls.metadata.capabilities]

    def by_asset_kind(self, asset_kind: str) -> list[type[ScannerPlugin]]:
        return [
            cls
            for cls in self._plugins.values()
            if asset_kind in cls.metadata.supported_asset_kinds
        ]

    def by_required_permission(
        self,
        *,
        grant_type: PermissionGrantType | None = None,
        name: str | None = None,
    ) -> list[type[ScannerPlugin]]:
        """Find plugins that declare a particular required permission.

        Useful for surfacing "which plugins are blocked because the tenant
        did not consent to permission X?" in the admin UI.
        """
        out: list[type[ScannerPlugin]] = []
        for cls in self._plugins.values():
            for perm in cls.metadata.required_permissions:
                if grant_type is not None and perm.grant_type is not grant_type:
                    continue
                if name is not None and perm.name != name:
                    continue
                out.append(cls)
                break
        return out

    def filter(
        self,
        *,
        providers: Iterable[CloudProvider] | None = None,
        capabilities: Iterable[ScannerCapability] | None = None,
        asset_kinds: Iterable[str] | None = None,
    ) -> list[type[ScannerPlugin]]:
        """Compose multiple criteria with AND semantics.

        ``capabilities`` and ``asset_kinds`` use *any-overlap* semantics: a
        plugin matches if it declares at least one of the requested values.
        """
        providers_set = set(providers) if providers is not None else None
        capabilities_set = set(capabilities) if capabilities is not None else None
        asset_kinds_set = set(asset_kinds) if asset_kinds is not None else None

        out: list[type[ScannerPlugin]] = []
        for cls in self._plugins.values():
            meta = cls.metadata
            if providers_set is not None and meta.provider not in providers_set:
                continue
            if capabilities_set is not None and not capabilities_set.intersection(meta.capabilities):
                continue
            if asset_kinds_set is not None and not asset_kinds_set.intersection(
                meta.supported_asset_kinds
            ):
                continue
            out.append(cls)
        return out


#: Module-level shared registry. Plugins self-register on import (see
#: ``scanner.plugins.__init__``). The orchestrator uses this singleton by
#: default but can be passed a custom registry for testing.
default_registry = PluginRegistry()
