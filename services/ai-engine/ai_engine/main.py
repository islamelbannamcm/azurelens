"""AI engine worker entry point.

Skeleton only. In Phase 5 this will:
  - Consume `ai.summarize.requested` from Service Bus.
  - Route to the correct prompt template (executive / finding / remediation / campaign / copilot).
  - Retrieve grounding via per-tenant Azure AI Search index (RAG).
  - Call Azure OpenAI with Managed Identity (no keys).
  - Validate outputs (JSON schema + PII redaction + citation checks).
  - Persist audit log (redacted) in Cosmos DB.

CRITICAL SAFETY INVARIANTS (enforced once code exists):
  - The AI never produces findings; it only summarizes structured inputs.
  - Per-tenant RAG: a tenant can only ever retrieve its own data.
  - Tool-use outputs are JSON-schema validated before any side effect.
  - Per-tenant token quotas enforced.

NO Azure OpenAI / AI Search calls happen here yet. NO keys are read.
See docs/ARCHITECTURE.md § 8 and docs/SECURITY_MODEL.md § 11.
"""

from __future__ import annotations

import sys


def run_once() -> int:
    """One-shot placeholder for local development."""
    print(
        "[ai-engine] skeleton — no AI calls performed. "
        "See docs/ROADMAP.md Phase 5."
    )
    return 0


def main() -> int:
    # TODO(phase-5): subcommands:
    #   - render --template <id> --input <path>  : render a single template (dev/testing)
    #   - serve                                  : long-running consumer loop
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
