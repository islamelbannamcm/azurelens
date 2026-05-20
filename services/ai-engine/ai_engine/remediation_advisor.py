"""Remediation advisor.

Produces ``RemediationRecommendation`` objects in two phases:

  1. **Deterministic** (this branch, Phase 6) — look up a remediation
     template by ``finding_type`` from a small built-in library, fill
     the audience-appropriate steps, decide an ``ApprovalRequirement``,
     and return. No AI involvement.

  2. **AI-enhanced** (Phase 5) — the same recommendation is then passed
     to the AI engine which rewrites the prose for the requested
     audience (executive, technical, IT manager) while preserving every
     step and approval marker. The AI MAY NOT add, remove, or reorder
     steps. ``ai_enhanced`` flips to True.

The two-phase split keeps audits unambiguous: if AI is down, customers
still get correct, ordered, executable remediations — just in default
language.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

from ai_engine.contracts import (
    ApprovalRequirement,
    Audience,
    RemediationRecommendation,
    RemediationStep,
    RemediationStepKind,
)


# ---------------------------------------------------------------------------
# Built-in library (tiny — full library lives in services/remediation/ later)
# ---------------------------------------------------------------------------


_TEMPLATE_LIBRARY: dict[str, dict] = {
    # Identity
    "identity.mfa.privileged.missing": {
        "title": "Enforce phishing-resistant MFA for privileged roles",
        "summary": (
            "Privileged principals must satisfy a phishing-resistant authentication "
            "method (FIDO2 / certificate) via a Conditional Access policy targeting "
            "all directory roles."
        ),
        "prerequisites": [
            "Inventory privileged role assignments (`Microsoft.RoleManagement`).",
            "Confirm the platform multi-tenant app has `Policy.ReadWrite.ConditionalAccess`.",
            "Define an emergency-access (break-glass) account excluded from the policy.",
        ],
        "steps": [
            {
                "kind": RemediationStepKind.MS_GRAPH,
                "title": "Create a Conditional Access policy requiring phishing-resistant MFA",
                "description": (
                    "Target all users in any directory role; require an authentication "
                    "strength of `phishingResistantMfa`."
                ),
                "code": (
                    "# POST https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies\n"
                    "# body example managed by the platform's remediation library"
                ),
                "approval_required": ApprovalRequirement.DUAL_CONTROL,
                "estimated_minutes": 30,
            },
            {
                "kind": RemediationStepKind.DOC_LINK,
                "title": "Reference: Microsoft Entra Conditional Access — authentication strengths",
                "description": "Microsoft Learn reference for authentication strengths.",
                "code": None,
                "approval_required": ApprovalRequirement.NONE,
                "estimated_minutes": 0,
            },
        ],
        "rollback": [
            {
                "kind": RemediationStepKind.MS_GRAPH,
                "title": "Disable the new Conditional Access policy",
                "description": "Set the policy's `state` to `disabled` if the rollout causes outages.",
                "code": None,
                "approval_required": ApprovalRequirement.DUAL_CONTROL,
                "estimated_minutes": 5,
            }
        ],
        "estimated_minutes": 30,
        "risk_reduction_estimate": 20,
        "approval_required": ApprovalRequirement.DUAL_CONTROL,
    },
    # Azure exposure
    "azure.network.rdp_public_exposed": {
        "title": "Restrict RDP to Azure Bastion / corporate ranges",
        "summary": (
            "Deny ingress on TCP/3389 from the public internet and require Azure "
            "Bastion (or a narrow allowlist of corporate IP ranges) for remote "
            "administration."
        ),
        "prerequisites": [
            "Identify all VMs with public RDP via Azure Resource Graph.",
            "Ensure Azure Bastion is deployed in the affected VNet or its hub.",
        ],
        "steps": [
            {
                "kind": RemediationStepKind.AZURE_CLI,
                "title": "Update NSG rule to deny public RDP",
                "description": (
                    "Restrict the NSG rule allowing RDP to internal CIDRs only."
                ),
                "code": (
                    "az network nsg rule update -g <rg> --nsg-name <nsg> "
                    "--name allow-rdp --source-address-prefixes 10.0.0.0/8 --access Deny"
                ),
                "approval_required": ApprovalRequirement.SINGLE_APPROVER,
                "estimated_minutes": 15,
            },
            {
                "kind": RemediationStepKind.AZURE_POLICY,
                "title": "Assign 'Allow only Azure Bastion for RDP' built-in policy",
                "description": "Deploy the built-in policy at subscription / management-group scope.",
                "code": None,
                "approval_required": ApprovalRequirement.CHANGE_ADVISORY,
                "estimated_minutes": 30,
            },
        ],
        "rollback": [
            {
                "kind": RemediationStepKind.AZURE_CLI,
                "title": "Re-allow the prior CIDR if the restriction breaks legitimate access",
                "description": "Revert the NSG rule to its previous source-address-prefixes.",
                "code": None,
                "approval_required": ApprovalRequirement.SINGLE_APPROVER,
                "estimated_minutes": 5,
            }
        ],
        "estimated_minutes": 45,
        "risk_reduction_estimate": 18,
        "approval_required": ApprovalRequirement.CHANGE_ADVISORY,
    },
    # Storage
    "azure.storage.public_access": {
        "title": "Disable public access on the storage account",
        "summary": (
            "Set the storage account network rules to deny by default; require "
            "Private Endpoints for tenant access."
        ),
        "prerequisites": [
            "Inventory applications that read/write the storage account.",
            "Confirm Private Endpoint connectivity from those applications.",
        ],
        "steps": [
            {
                "kind": RemediationStepKind.AZURE_CLI,
                "title": "Set default network action to Deny",
                "description": "Block public access by default.",
                "code": (
                    "az storage account update -g <rg> -n <sa> --default-action Deny"
                ),
                "approval_required": ApprovalRequirement.SINGLE_APPROVER,
                "estimated_minutes": 10,
            },
            {
                "kind": RemediationStepKind.AZURE_CLI,
                "title": "Disable blob public access",
                "description": "Deny anonymous blob access at the account level.",
                "code": (
                    "az storage account update -g <rg> -n <sa> --allow-blob-public-access false"
                ),
                "approval_required": ApprovalRequirement.SINGLE_APPROVER,
                "estimated_minutes": 5,
            },
        ],
        "rollback": [],
        "estimated_minutes": 30,
        "risk_reduction_estimate": 12,
        "approval_required": ApprovalRequirement.SINGLE_APPROVER,
    },
}


# Fallback used when no template matches a finding_type.
_FALLBACK_TEMPLATE: dict = {
    "title": "Review finding and apply Microsoft baseline guidance",
    "summary": (
        "No specific remediation template is currently mapped to this "
        "finding_type. Review the Microsoft Cloud Security Benchmark and "
        "CIS Azure / M365 baselines for the affected control area."
    ),
    "prerequisites": [],
    "steps": [
        {
            "kind": RemediationStepKind.DOC_LINK,
            "title": "Microsoft Cloud Security Benchmark (MCSB)",
            "description": "Open the MCSB control catalog and locate the matching control id.",
            "code": None,
            "approval_required": ApprovalRequirement.NONE,
            "estimated_minutes": 15,
        },
        {
            "kind": RemediationStepKind.MANUAL,
            "title": "Document mitigating controls and re-scan",
            "description": (
                "Document compensating controls if remediation is not feasible; "
                "request a re-scan after applying the change."
            ),
            "code": None,
            "approval_required": ApprovalRequirement.SINGLE_APPROVER,
            "estimated_minutes": 60,
        },
    ],
    "rollback": [],
    "estimated_minutes": 75,
    "risk_reduction_estimate": 5,
    "approval_required": ApprovalRequirement.SINGLE_APPROVER,
}


# ---------------------------------------------------------------------------
# Advisor
# ---------------------------------------------------------------------------


class RemediationAdvisor:
    """Produce deterministic remediation recommendations.

    The orchestrator constructs one of these per analysis call. In Phase 5+
    the AI engine receives the result of ``recommend(...)`` plus the
    ``finding.remediate.v1`` prompt template and rewrites the prose for
    the requested audience.
    """

    def __init__(self, library: dict[str, dict] | None = None) -> None:
        self._library: dict[str, dict] = library or _TEMPLATE_LIBRARY

    # ----------------------------------------------------------------- public

    def recommend(
        self,
        *,
        tenant_id: UUID,
        finding_id: UUID | None,
        finding_type: str,
        audience: Audience = Audience.TECHNICAL,
        citations: list[str] | None = None,
    ) -> RemediationRecommendation:
        """Return a deterministic ``RemediationRecommendation``.

        TODO(phase-5): pass this object to ``AIEngine.enhance_remediation()``
        when an AI deployment is available; that helper preserves the step
        list verbatim and rewrites only the prose ``title`` and ``summary``
        and per-step ``description`` to the requested audience's language.
        """
        template = self._library.get(finding_type, _FALLBACK_TEMPLATE)
        steps = [_step_from_dict(d) for d in template["steps"]]
        rollback = [_step_from_dict(d) for d in template["rollback"]]

        approval = template.get("approval_required", ApprovalRequirement.SINGLE_APPROVER)
        # Escalate approval if any step requires a higher tier.
        for step in steps:
            if _approval_rank(step.approval_required) > _approval_rank(approval):
                approval = step.approval_required

        return RemediationRecommendation(
            recommendation_id=uuid4(),
            tenant_id=tenant_id,
            finding_id=finding_id,
            audience=audience,
            title=template["title"],
            summary=template["summary"],
            steps=steps,
            rollback=rollback,
            prerequisites=list(template.get("prerequisites", [])),
            estimated_minutes=template.get("estimated_minutes"),
            risk_reduction_estimate=template.get("risk_reduction_estimate"),
            approval_required=approval,
            citations=list(citations or []),
            ai_enhanced=False,
            generated_at=_utcnow(),
        )

    def enhance_with_ai(
        self,
        recommendation: RemediationRecommendation,
        *,
        audience: Audience | None = None,
    ) -> RemediationRecommendation:
        """Placeholder for AI rewriting (Phase 5).

        In this branch the input is returned unchanged so deterministic
        behaviour is preserved. When Azure OpenAI is wired in Phase 5 the
        contract is:

          * inputs: this recommendation + the ``finding.remediate.v1`` prompt
            template + the original finding/asset evidence,
          * outputs: a copy of the recommendation with rewritten ``title``,
            ``summary``, and per-step ``description``,
          * invariants: steps[*].kind, steps[*].code, steps[*].approval_required,
            and the *count + order* of steps + rollback are preserved exactly,
          * ``ai_enhanced`` is set to True only if all invariants pass the
            grounding validator.

        TODO(phase-5): wire AIEngine.enhance_remediation(recommendation, audience).
        """
        _ = audience  # reserved for the AI-side audience-tone selection
        return recommendation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _step_from_dict(d: dict) -> RemediationStep:
    return RemediationStep(
        kind=d["kind"],
        title=d["title"],
        description=d["description"],
        code=d.get("code"),
        docs_url=d.get("docs_url"),
        approval_required=d.get("approval_required", ApprovalRequirement.SINGLE_APPROVER),
        estimated_minutes=d.get("estimated_minutes"),
    )


def _approval_rank(req: ApprovalRequirement) -> int:
    return {
        ApprovalRequirement.NONE: 0,
        ApprovalRequirement.SINGLE_APPROVER: 1,
        ApprovalRequirement.DUAL_CONTROL: 2,
        ApprovalRequirement.CHANGE_ADVISORY: 3,
    }[req]


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


__all__ = ["RemediationAdvisor"]
