"""/api/v1/remediations — remediation actions, templates, approval (demo mode).

Future work (Phase 1 → 4):
  * Replace demo_service with persistence; route approvals through Logic
    Apps Standard with 4-eyes / change-advisory gates.
  * Mount per-tenant audit trail of every approval transition.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, status

from app.demo import demo_service
from app.demo.service import RemediationRoadmapSummary
from app.models.report import RemediationAction, RemediationStatus, RemediationTemplate

router = APIRouter()


@router.get(
    "",
    response_model=list[RemediationAction],
    summary="List remediation actions",
)
async def list_remediation_actions(
    remediation_status: RemediationStatus | None = Query(default=None, alias="status"),
) -> list[RemediationAction]:
    return demo_service.list_remediation_actions(status=remediation_status)


@router.get(
    "/templates",
    response_model=list[RemediationTemplate],
    summary="List remediation templates",
)
async def list_templates() -> list[RemediationTemplate]:
    return demo_service.list_remediation_templates()


@router.get(
    "/roadmap",
    response_model=RemediationRoadmapSummary,
    summary="Prioritized remediation roadmap (dashboard composite)",
)
async def remediation_roadmap() -> RemediationRoadmapSummary:
    return demo_service.remediation_roadmap()


@router.get(
    "/{action_id}",
    response_model=RemediationAction,
    summary="Get one remediation action",
)
async def get_action(action_id: UUID) -> RemediationAction:
    action = demo_service.get_remediation_action(action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="remediation_action_not_found"
        )
    return action


@router.post(
    "/{action_id}/approve",
    response_model=RemediationAction,
    summary="Approve a remediation action (no execution in demo mode)",
)
async def approve_action(action_id: UUID) -> RemediationAction:
    # TODO(phase-4): enforce 4-eyes / change-advisory gates via Logic Apps Standard.
    # TODO(phase-4): write an audit entry capturing the approving identity.
    updated = demo_service.approve_remediation_action(action_id)
    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="remediation_action_not_found"
        )
    return updated
