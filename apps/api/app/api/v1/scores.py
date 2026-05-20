"""/api/v1/scores — per-tenant posture scores.

Demo-mode reads only. The real worker (``services/risk-engine``) writes
to ``scores_current`` and ``scores_history`` (see docs/SCHEMA_DESIGN.md
§ 7) in Phase 1+; this surface is shape-compatible with that future
persistence.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.demo import demo_service
from app.models import Score, ScoreKind

router = APIRouter()


class ScoreOverview(BaseModel):
    """Roll-up of all current scores for a tenant."""

    overall: Score
    domains: list[Score] = Field(default_factory=list)


class ScoreHistoryPoint(BaseModel):
    recorded_at: datetime
    value: int = Field(..., ge=0, le=100)


class ScoreHistory(BaseModel):
    score_kind: ScoreKind
    points: list[ScoreHistoryPoint]


@router.get(
    "",
    response_model=list[Score],
    summary="List all current scores for the tenant",
)
async def list_scores() -> list[Score]:
    return demo_service.list_scores()


@router.get(
    "/overview",
    response_model=ScoreOverview,
    summary="Overall score + per-domain breakdown in one payload",
)
async def score_overview() -> ScoreOverview:
    overall = demo_service.get_score(ScoreKind.OVERALL)
    if overall is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="overall_score_not_available",
        )
    domains = [s for s in demo_service.list_scores() if s.score_kind is not ScoreKind.OVERALL]
    return ScoreOverview(overall=overall, domains=domains)


@router.get(
    "/{kind}",
    response_model=Score,
    summary="Get the current score for one domain",
)
async def get_score(kind: ScoreKind) -> Score:
    score = demo_service.get_score(kind)
    if score is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="score_not_found",
        )
    return score


@router.get(
    "/{kind}/history",
    response_model=ScoreHistory,
    summary="Get the recent score history for one domain",
)
async def get_score_history(
    kind: ScoreKind,
    days: int = Query(default=14, ge=1, le=90),
) -> ScoreHistory:
    series = demo_service.get_score_history(kind, days=days)
    return ScoreHistory(
        score_kind=kind,
        points=[ScoreHistoryPoint(recorded_at=ts, value=v) for ts, v in series],
    )
