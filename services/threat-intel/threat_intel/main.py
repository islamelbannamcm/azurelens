"""Threat Intelligence worker entry point.

Skeleton only. In Phase 2 this will:
  - Run per-source timer-triggered ingestion jobs.
  - Normalize each source to the internal STIX-aligned schema.
  - Maintain the shared TI corpus in Cosmos DB + AI Search.
  - Run correlation workers on `finding.normalized` and `ti.indicator.normalized`.
  - Emit `correlation.hit` events to boost risk scoring.

NO external network calls are made here. NO API keys are read.
See docs/ARCHITECTURE.md § 7 and docs/SCHEMA_DESIGN.md § 5.
"""

from __future__ import annotations

import sys


def run_once() -> int:
    """One-shot placeholder for local development."""
    print(
        "[threat-intel] skeleton — no ingestion or correlation performed. "
        "See docs/ROADMAP.md Phase 2."
    )
    return 0


def main() -> int:
    # TODO(phase-2): split into:
    #   - cmd `ingest --source <id>`     : pull a single source
    #   - cmd `normalize --batch <uri>`  : normalize an ADLS batch
    #   - cmd `correlate --tenant <id>`  : (re)build correlations for a tenant
    #   - cmd `serve`                    : long-running consumer loop
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
