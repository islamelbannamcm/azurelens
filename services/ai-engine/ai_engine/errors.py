"""AI-engine exception hierarchy.

The orchestrator catches these at the analysis-call boundary and converts
them into ``SafetyDecisionOutcome.BLOCK`` results with structured context.
Exceptions must never propagate past one analysis call.

Categories
----------
AIEngineError              : base
AIConfigError              : engine / template configuration is invalid
AIPromptError              : template missing, malformed, or version pinned to a removed id
AISafetyError              : prompt-input or output-side safety check failed
AIGroundingError           : grounding requirement violated (uncited claim, missing evidence)
PromptInjectionDetectedError : detected attempt to override system prompt / tools
AIContentFilteredError     : Azure OpenAI content filter blocked the output (Phase 5+)
AIModelUnavailableError    : configured model deployment is unreachable
AIQuotaExceededError       : per-tenant or platform-wide token / call budget exhausted
TenantIsolationError       : prompt / output referenced a different tenant's data (P0)
"""

from __future__ import annotations

from typing import Any


class AIEngineError(Exception):
    """Base class for all AI-engine errors."""

    code: str = "ai_error"

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.context: dict[str, Any] = context or {}


class AIConfigError(AIEngineError):
    code = "ai_config_error"


class AIPromptError(AIEngineError):
    code = "ai_prompt_error"


class AISafetyError(AIEngineError):
    code = "ai_safety_error"


class AIGroundingError(AIEngineError):
    """Grounding requirement violated.

    Examples: an AI output makes a claim that does not reference any
    supplied ``GroundedEvidenceItem``; a numeric assertion does not match
    any evidence; an entity (asset id, user oid, CVE) appears that is not
    in the evidence bundle.
    """

    code = "ai_grounding_error"


class PromptInjectionDetectedError(AISafetyError):
    """Heuristic / Prompt-Shield signal that the input attempted to override the system prompt."""

    code = "ai_prompt_injection"


class AIContentFilteredError(AIEngineError):
    code = "ai_content_filtered"


class AIModelUnavailableError(AIEngineError):
    code = "ai_model_unavailable"


class AIQuotaExceededError(AIEngineError):
    code = "ai_quota_exceeded"


class TenantIsolationError(AIEngineError):
    """A request or output referenced data outside the requesting tenant (P0).

    See docs/SCHEMA_DESIGN.md § 12 and docs/PROMPT_SAFETY_MODEL.md.
    """

    code = "ai_tenant_isolation_error"
