"""Built-in threat-intelligence connectors.

Importing this package triggers each connector module to self-register
against ``threat_intel.registry.default_registry``. The ingestion
orchestrator imports ``threat_intel.connectors`` once at startup;
user-supplied connectors follow the same convention from their own
packages.

All connectors in this branch are STUBS — no network calls, no SDK calls,
no API keys are read. See docs/THREAT_INTEL_ARCHITECTURE.md.
"""

from __future__ import annotations

# Side-effect imports drive connector self-registration.
from threat_intel.connectors import (  # noqa: F401
    abuse_ch,
    alienvault_otx,
    cisa_kev,
    github_advisories,
    microsoft_defender_ti,
    misp,
    mitre_attack,
    nvd,
    opencti,
    sentinel_ti,
    virustotal,
)
