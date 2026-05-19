"""Scanner worker entry point.

Skeleton only. In Phase 1 this will:
  - Connect to Service Bus and consume `scan.requested` events.
  - Dispatch to the appropriate sub-scanner (azure / m365 / intune / defender / purview).
  - Fan out per subscription / user batch via Durable Functions orchestrators.
  - Write raw evidence to ADLS Gen2 and emit `finding.raw` events.

NO Microsoft API calls happen here yet. NO credentials are read.
See docs/ARCHITECTURE.md § 4.3 for the target design.
"""

from __future__ import annotations

import sys


def run_once() -> int:
    """One-shot placeholder.

    Real implementation will:
      1. resolve_tenant_context(event)
      2. acquire token via Managed Identity
      3. enumerate target scope (subscription / tenant)
      4. parallel-fetch with rate limiting + idempotency keys
      5. normalize -> RawFinding envelopes
      6. persist evidence -> ADLS, emit -> Service Bus
    """
    print("[scanner] skeleton — no scanning performed. See docs/ROADMAP.md Phase 1.")
    return 0


def main() -> int:
    """Console-script entry point (see pyproject.toml `[project.scripts]`)."""
    # TODO(phase-1): replace with a long-running consumer loop.
    #   - graceful shutdown on SIGTERM (Container Apps / Functions lifecycle)
    #   - health/liveness probe sidecar
    #   - structured logging + OpenTelemetry traces
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
