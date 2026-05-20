"""High-level calculator that turns inputs into score outputs.

This is the boundary the orchestrator (and tests) interact with. It owns:

  * applying a ``ScoringPolicy`` to one or more inputs,
  * computing ``RiskScoreOutput`` / ``DomainScoreOutput`` / ``OverallScoreOutput``,
  * delegating reason generation to ``explainability.py``,
  * stamping every output with the policy reference + timestamp.

No I/O, no persistence — the worker in Phase 1+ wraps this in a Service
Bus consumer that fetches inputs from Cosmos / SQL and writes outputs
back. See docs/RISK_SCORING_MODEL.md.
"""

from __future__ import annotations

from datetime import datetime, timezone

from risk_engine.contracts import (
    DomainScoreInput,
    DomainScoreOutput,
    FindingScoreInput,
    OverallScoreInput,
    OverallScoreOutput,
    RiskScoreOutput,
    ScoreBand,
)
from risk_engine.errors import RiskEngineError
from risk_engine.formulas import (
    classify_band,
    classify_finding_band,
    compute_domain_posture_score,
    compute_finding_risk_score,
    compute_overall_posture_score,
    to_int_score,
)
from risk_engine.policy import ScoringPolicy, default_policy


# ---------------------------------------------------------------------------
# Calculator
# ---------------------------------------------------------------------------


class RiskCalculator:
    """Stateless wrapper around the formulas + policy + explainability."""

    def __init__(self, policy: ScoringPolicy | None = None) -> None:
        self._policy = policy or default_policy()

    @property
    def policy(self) -> ScoringPolicy:
        return self._policy

    # ----------------------------------------------------------------- finding

    def score_finding(self, fi: FindingScoreInput) -> RiskScoreOutput:
        """Score one finding."""
        # Import here to break the cycle (explainability imports contracts only).
        from risk_engine.explainability import explain_finding_score

        weights = self._policy.weights
        score, breakdown = compute_finding_risk_score(fi, weights)
        band_str = classify_finding_band(score, weights)

        try:
            reasons = explain_finding_score(fi, breakdown, weights)
        except RiskEngineError:
            # Explainability is best-effort; never block a score on it.
            reasons = []

        return RiskScoreOutput(
            finding_id=fi.finding_id,
            tenant_id=fi.tenant_id,
            score=score,
            band=ScoreBand(band_str),
            breakdown=breakdown,
            reasons=reasons,
            policy=self._policy.ref(),
            calculated_at=_utcnow(),
        )

    def score_findings(self, inputs: list[FindingScoreInput]) -> list[RiskScoreOutput]:
        return [self.score_finding(fi) for fi in inputs]

    # ----------------------------------------------------------------- domain

    def score_domain(self, di: DomainScoreInput) -> DomainScoreOutput:
        """Aggregate one domain's findings into a posture sub-score (higher = better)."""
        from risk_engine.explainability import explain_domain_score

        weights = self._policy.weights
        score, factor_breakdown, contributors = compute_domain_posture_score(di, weights)
        band_str = classify_band(score, weights)

        try:
            reasons = explain_domain_score(di, factor_breakdown, weights)
        except RiskEngineError:
            reasons = []

        return DomainScoreOutput(
            tenant_id=di.tenant_id,
            score_kind=di.score_kind,
            value=to_int_score(score),
            band=ScoreBand(band_str),
            contributing_finding_ids=contributors,
            factor_breakdown=factor_breakdown,
            reasons=reasons,
            policy=self._policy.ref(),
            calculated_at=_utcnow(),
        )

    # ---------------------------------------------------------------- overall

    def score_overall(self, oi: OverallScoreInput) -> OverallScoreOutput:
        """Compute the tenant's weighted overall posture score (higher = better)."""
        from risk_engine.explainability import explain_overall_score

        weights = self._policy.weights
        score = compute_overall_posture_score(oi, weights)
        band_str = classify_band(score, weights)

        try:
            reasons = explain_overall_score(oi, weights)
        except RiskEngineError:
            reasons = []

        return OverallScoreOutput(
            tenant_id=oi.tenant_id,
            value=to_int_score(score),
            band=ScoreBand(band_str),
            sub_scores={k: to_int_score(v) for k, v in oi.sub_scores.items()},
            reasons=reasons,
            policy=self._policy.ref(),
            calculated_at=_utcnow(),
        )


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)
