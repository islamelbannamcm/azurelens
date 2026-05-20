"""Prompt + output safety layer.

Two evaluation surfaces are exposed:

  * ``SafetyEvaluator.evaluate_inputs(request)`` — run BEFORE the prompt
    is sent (in Phase 5+, to Azure OpenAI). Catches prompt injection,
    cross-tenant references in evidence summaries, PII / secret leakage
    that the orchestrator should have already redacted.

  * ``SafetyEvaluator.evaluate_output(text, request)`` — run AFTER the LLM
    returns (or, in this skeleton, after the deterministic generator
    runs). Catches ungrounded assertions, residual PII / secrets,
    hallucination markers, and references to other tenants.

All checks here are **deterministic and rule-based** — no LLM, no
randomness, no network. This makes them auditable and trivially
testable. Real Azure AI Content Safety + Prompt Shields integration is
wired in Phase 5 (see TODOs below); their decisions are *combined* with
this layer's, never replaced by it.

See docs/PROMPT_SAFETY_MODEL.md for the policy this layer enforces.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from uuid import UUID, uuid4

from ai_engine.contracts import (
    AIAnalysisRequest,
    GroundedEvidenceItem,
    PromptSafetyDecision,
    SafetyDecisionOutcome,
    SafetyRiskCategory,
)


# ---------------------------------------------------------------------------
# Pattern catalogs (deterministic; no remote rules)
# ---------------------------------------------------------------------------


# Prompt-injection signatures. Conservative; the orchestrator pairs this
# with the Azure AI Content Safety Prompt Shield (Phase 5).
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bignore (all )?(previous|above) (instructions|prompts|rules)\b",
        r"\bdisregard (the )?(system|previous|above) (prompt|message|instructions)\b",
        r"\boverride( all)? (your|the) (instructions|policies|rules)\b",
        r"\b(act|behave) as (?:if you are|a) (?:no|not) bound by\b",
        r"\bsystem\s*:\s*you are now\b",
        r"\bnew (system )?prompt\b",
        r"\breveal (the|your) (system )?prompt\b",
        r"\bjailbreak\b",
        r"\bDAN\b",
        r"\benable developer mode\b",
        r"\bprint( the| your)? (full )?system (prompt|instructions)\b",
        r"\bforget (?:everything|your instructions)\b",
        r"\brepeat (?:above|prior) (text|content) verbatim\b",
    )
)

# Secret-leak signatures (lightweight, defense-in-depth on top of orchestrator redaction).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("api_key_generic", re.compile(r"\b(?:api[_-]?key|secret)[\s:=\"']+[A-Za-z0-9_\-]{16,}\b", re.IGNORECASE)),
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("azure_storage_key", re.compile(r"\b[A-Za-z0-9+/]{86}==\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
)

# PII signatures used for residual redaction; the orchestrator already redacts
# UPNs / emails / IPs before evidence is built, so finding any here is unusual.
_PII_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone_e164", re.compile(r"\+[1-9]\d{6,14}\b")),
    ("ssn_us", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("credit_card", re.compile(r"\b(?:\d[ -]?){13,19}\b")),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
)

# Hallucination markers — phrases an LLM commonly emits when it lacks evidence.
_HALLUCINATION_MARKERS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bin my training data\b",
        r"\bas of (?:my last update|the knowledge cutoff)\b",
        r"\bI cannot (?:verify|confirm) (?:this|that)\b",
        r"\bI (?:think|believe|guess|assume)\b",
        r"\bit is likely that\b",
        r"\bmight be the case\b",
        r"\bprobably\b",
        r"\bI don't have access to\b",
    )
)

# Tenant-isolation signatures: explicit cross-tenant references the orchestrator
# would NEVER place in a prompt. If they appear in OUTPUT, it's a P0.
_TENANT_REFERENCE_PATTERN = re.compile(
    r"\btenant[_\-]?id\s*[:=]\s*([0-9a-fA-F\-]{8,40})", re.IGNORECASE
)

# Maximum length of the prompt input we'll accept; longer than the largest
# legitimate template + evidence bundle by ~3x.
_MAX_PROMPT_INPUT_CHARS = 200_000


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class SafetyEvaluator:
    """Deterministic rule-based safety checks (no LLM, no network)."""

    # ----------------------------------------------------------------- inputs

    def evaluate_inputs(self, request: AIAnalysisRequest) -> PromptSafetyDecision:
        """Run safety checks on a request before any prompt is dispatched.

        The orchestrator MUST honor the returned outcome:
          * ``ALLOW``  → proceed.
          * ``REDACT`` → re-build the request with the listed redactions applied.
          * ``BLOCK``  → do not dispatch; surface a safe error to the caller.
        """
        risks: list[SafetyRiskCategory] = []
        redactions: list[str] = []
        detail_parts: list[str] = []

        # Size cap
        evidence_chars = sum(len(e.summary) for e in request.evidence)
        if evidence_chars > _MAX_PROMPT_INPUT_CHARS:
            risks.append(SafetyRiskCategory.UNAUTHORIZED_TOOL_USE)
            detail_parts.append(
                f"evidence size {evidence_chars} exceeds {_MAX_PROMPT_INPUT_CHARS} chars"
            )

        # Cross-tenant reference inside the evidence bundle
        for item in request.evidence:
            if _references_other_tenant(item.summary, request.tenant_id) or _references_other_tenant(
                _stringify_payload(item.redacted_payload), request.tenant_id
            ):
                risks.append(SafetyRiskCategory.CROSS_TENANT_REFERENCE)
                detail_parts.append(f"evidence_id={item.evidence_id} references another tenant")

        # Prompt-injection signatures inside evidence summaries.
        # (System prompts themselves are immutable; user-facing copilot inputs
        # are guarded at the API layer in addition to this check.)
        for item in request.evidence:
            if _matches_any(item.summary, _INJECTION_PATTERNS):
                risks.append(SafetyRiskCategory.PROMPT_INJECTION)
                detail_parts.append(
                    f"evidence_id={item.evidence_id} contains prompt-injection-like phrasing"
                )

        # Residual secret / PII checks (orchestrator should have redacted already)
        for item in request.evidence:
            secret_hits = _find_pattern_hits(item.summary, _SECRET_PATTERNS)
            if secret_hits:
                risks.append(SafetyRiskCategory.SECRET_EXPOSURE)
                redactions.extend(f"secret:{h}" for h in secret_hits)
            pii_hits = _find_pattern_hits(item.summary, _PII_PATTERNS)
            if pii_hits:
                risks.append(SafetyRiskCategory.PII_EXPOSURE)
                redactions.extend(f"pii:{h}" for h in pii_hits)

        # Outcome
        if (
            SafetyRiskCategory.PROMPT_INJECTION in risks
            or SafetyRiskCategory.CROSS_TENANT_REFERENCE in risks
            or SafetyRiskCategory.UNAUTHORIZED_TOOL_USE in risks
        ):
            outcome = SafetyDecisionOutcome.BLOCK
        elif redactions:
            outcome = SafetyDecisionOutcome.REDACT
        else:
            outcome = SafetyDecisionOutcome.ALLOW

        # TODO(phase-5):
        #   * call Azure AI Content Safety Prompt Shield with the merged
        #     prompt + evidence text; merge its decision with this one
        #     using *the strictest of the two*.
        #   * call Azure AI Content Safety text moderation in parallel
        #     for hate / sexual / self-harm / violence categories; map
        #     any non-`safe` decision to BLOCK.

        return PromptSafetyDecision(
            decision_id=uuid4(),
            outcome=outcome,
            risks=_dedupe(risks),
            redactions_applied=redactions,
            detail="; ".join(detail_parts),
            evaluated_at=_utcnow(),
        )

    # ----------------------------------------------------------------- output

    def evaluate_output(
        self,
        text: str,
        request: AIAnalysisRequest,
    ) -> tuple[PromptSafetyDecision, str]:
        """Run safety checks on the produced output. Returns ``(decision, sanitized_text)``.

        ``sanitized_text`` is the input with any required redactions applied.
        If the decision is ``BLOCK``, the orchestrator should NOT surface the
        text — only the decision detail (operator-facing).
        """
        risks: list[SafetyRiskCategory] = []
        redactions: list[str] = []
        sanitized = text

        # Secrets first — strictest redaction.
        for name, pattern in _SECRET_PATTERNS:
            if pattern.search(sanitized):
                risks.append(SafetyRiskCategory.SECRET_EXPOSURE)
                sanitized = pattern.sub("[REDACTED:secret]", sanitized)
                redactions.append(f"secret:{name}")

        # PII redaction.
        for name, pattern in _PII_PATTERNS:
            if pattern.search(sanitized):
                risks.append(SafetyRiskCategory.PII_EXPOSURE)
                sanitized = pattern.sub(f"[REDACTED:{name}]", sanitized)
                redactions.append(f"pii:{name}")

        # Cross-tenant reference in output is a P0.
        if _references_other_tenant(sanitized, request.tenant_id):
            risks.append(SafetyRiskCategory.CROSS_TENANT_REFERENCE)

        # Hallucination markers.
        if _matches_any(sanitized, _HALLUCINATION_MARKERS):
            risks.append(SafetyRiskCategory.HALLUCINATION_RISK)

        # Citation coverage. Empty output skips this check.
        if sanitized.strip() and request.evidence:
            allowed_tokens = {e.citation_token for e in request.evidence}
            used_tokens = set(_extract_citation_tokens(sanitized))
            if not used_tokens:
                risks.append(SafetyRiskCategory.UNGROUNDED_ASSERTION)
            elif used_tokens - allowed_tokens:
                risks.append(SafetyRiskCategory.UNSUPPORTED_CLAIM)

        # Outcome.
        if (
            SafetyRiskCategory.CROSS_TENANT_REFERENCE in risks
            or SafetyRiskCategory.UNGROUNDED_ASSERTION in risks
            or SafetyRiskCategory.UNSUPPORTED_CLAIM in risks
        ):
            outcome = SafetyDecisionOutcome.BLOCK
        elif redactions or SafetyRiskCategory.HALLUCINATION_RISK in risks:
            outcome = SafetyDecisionOutcome.REDACT
        else:
            outcome = SafetyDecisionOutcome.ALLOW

        # TODO(phase-5):
        #   * call Azure AI Content Safety output moderation; merge with
        #     the strictest outcome.
        #   * call Prompt Shield "Document" mode if the response was built
        #     from large grounding documents.

        decision = PromptSafetyDecision(
            decision_id=uuid4(),
            outcome=outcome,
            risks=_dedupe(risks),
            redactions_applied=redactions,
            detail="",
            evaluated_at=_utcnow(),
        )
        return decision, sanitized


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _matches_any(text: str, patterns: tuple[re.Pattern[str], ...]) -> bool:
    return any(p.search(text) for p in patterns)


def _find_pattern_hits(
    text: str, patterns: tuple[tuple[str, re.Pattern[str]], ...]
) -> list[str]:
    return [name for name, p in patterns if p.search(text)]


def _stringify_payload(payload: dict[str, object]) -> str:
    """Serialize a redacted payload to a stable string for pattern matching."""
    # We avoid json.dumps to keep the output predictable; the orchestrator
    # already ensures payload values are stringifiable scalars or short lists.
    parts = []
    for k, v in payload.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


def _references_other_tenant(text: str, allowed_tenant_id: UUID) -> bool:
    allowed = str(allowed_tenant_id).lower()
    for match in _TENANT_REFERENCE_PATTERN.finditer(text):
        if match.group(1).lower() != allowed:
            return True
    return False


_CITATION_RX = re.compile(r"\[\[evi:[A-Za-z0-9_\-]{1,40}\]\]")


def _extract_citation_tokens(text: str) -> list[str]:
    return _CITATION_RX.findall(text)


def _dedupe(items: list[SafetyRiskCategory]) -> list[SafetyRiskCategory]:
    seen: set[SafetyRiskCategory] = set()
    out: list[SafetyRiskCategory] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)
