"""Risk-engine exception hierarchy.

Calculators and explainers raise these; the orchestrator catches them and
records structured error context. Exceptions must never propagate past a
single scoring call.

Categories
----------
RiskEngineError      : base
RiskConfigError      : policy / weight configuration is invalid
RiskInputError       : scoring input violates a contract (e.g. negative confidence)
RiskPolicyError      : referenced policy does not exist or has incompatible version
BoundsViolationError : an intermediate or final score landed outside [0, 100]
                        — almost always a programming bug; converted to a P1
ExplainabilityError  : reason templating failed
"""

from __future__ import annotations

from typing import Any


class RiskEngineError(Exception):
    """Base class for all risk-engine errors."""

    code: str = "risk_error"

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.context: dict[str, Any] = context or {}


class RiskConfigError(RiskEngineError):
    code = "risk_config_error"


class RiskInputError(RiskEngineError):
    code = "risk_input_error"


class RiskPolicyError(RiskEngineError):
    code = "risk_policy_error"


class BoundsViolationError(RiskEngineError):
    """An intermediate or final score went outside [0, 100].

    Always a programming bug. The orchestrator clamps and continues, but
    raises an alert so the offending formula can be fixed.
    """

    code = "risk_bounds_violation"


class ExplainabilityError(RiskEngineError):
    code = "risk_explainability_error"
