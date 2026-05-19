"""Built-in scanner plugins.

Importing this package triggers each plugin module to self-register against
``scanner.registry.default_registry``. The orchestrator imports
``scanner.plugins`` once at startup; user-supplied plugins follow the same
convention from their own packages.

All plugins in this branch are STUBS — no Microsoft Graph, Azure SDK,
Defender, Sentinel, Intune, or Purview calls are made. See
docs/SCANNER_ARCHITECTURE.md for the plugin lifecycle.
"""

from __future__ import annotations

# Side-effect imports drive plugin self-registration.
from scanner.plugins import (  # noqa: F401
    azure_resource_graph,
    defender_cloud,
    entra_identity,
    intune_device,
    m365_security,
    purview,
    sentinel,
)
