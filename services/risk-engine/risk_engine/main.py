"""Risk-engine worker entry point.

Skeleton only. In Phase 1+ this will:
  - Consume `finding.normalized` and `correlation.hit` from Service Bus.
  - Resolve the current ScoringPolicy for the tenant (with version pinning).
  - Compute deterministic, explainable scores.
  - Update SQL (`findings.risk_score`, `scores_current`) and snapshot to `scores_history`.
  - Emit `score.updated` for downstream consumers.

NO Azure SDK calls happen here yet. NO secrets are read.
See docs/ARCHITECTURE.md § 4.5 and docs/SCHEMA_DESIGN.md § 7.
"""

from __future__ import annotations

import sys


def run_once() -> int:
    """One-shot placeholder for local development."""
    print(
        "[risk-engine] skeleton — no scoring performed. "
        "See docs/ROADMAP.md Phase 1 / 2."
    )
    return 0


def main() -> int:
    # TODO(phase-1): subcommands:
    #   - score-one --finding <id>     : ad-hoc score for debugging
    #   - rescore --tenant <id>        : rescore all findings under a policy bump
    #   - serve                        : long-running consumer loop
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
