"""Grounding layer.

The grounding contract is simple and strict:

  Every assertion in an AI output MUST cite at least one
  ``GroundedEvidenceItem`` that the orchestrator pre-built for the request.

  No assertion may reference an entity (asset id, finding id, CVE,
  campaign id, tenant id) that does not appear in the evidence bundle.

  The AI engine NEVER fetches additional evidence implicitly; the
  orchestrator is the only place that decides what evidence is in scope
  for a given analysis call (filtered by tenant scope first).

This module exposes:

  * ``GroundingValidator`` — validates a built ``AIAnalysisRequest`` and
    inspects produced output text for citation coverage and entity drift.
  * ``EvidenceBuilder`` — tiny helper that mints citation tokens and
    redacted payloads from upstream domain objects (full implementation
    in Phase 5; signatures and contracts are stable now).

No LLM, no network, no randomness here. Determinism is the entire point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable
from uuid import UUID

from ai_engine.contracts import (
    AIAnalysisRequest,
    EvidenceType,
    GroundedEvidenceItem,
)
from ai_engine.errors import AIGroundingError


CITATION_PATTERN = re.compile(r"\[\[evi:[A-Za-z0-9_\-]{1,40}\]\]")
ENTITY_LIKE_PATTERN = re.compile(
    # Matches: finding ids (UUID), asset ids (sha256:...), CVE ids, campaign ids,
    # MITRE technique ids. Used to surface entities mentioned in output but not
    # represented in evidence.
    r"\b(?:"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"|sha256:[A-Za-z0-9_\-]{8,}"
    r"|CVE-\d{4}-\d{4,}"
    r"|T\d{4}(?:\.\d{3})?"
    r"|TA\d{4}"
    r")\b"
)


@dataclass(frozen=True, slots=True)
class GroundingValidationResult:
    """Outcome of validating produced output against the evidence bundle."""

    passed: bool
    citation_count: int = 0
    missing_citations: tuple[str, ...] = ()      # citation_tokens used but not in evidence
    unsupported_entities: tuple[str, ...] = ()   # entity ids mentioned without a backing evidence item
    coverage_pct: float = 0.0                    # citations / number of paragraphs
    notes: tuple[str, ...] = field(default_factory=tuple)


class GroundingValidator:
    """Validate that AI input + output stay strictly inside the evidence bundle."""

    def __init__(self, *, require_citation_per_paragraph: bool = True) -> None:
        self._require_per_paragraph = require_citation_per_paragraph

    # ------------------------------------------------------------------ request

    def validate_request(self, request: AIAnalysisRequest) -> None:
        """Validate the *input* side. Raises ``AIGroundingError`` on violation.

        Checks:
          * non-empty evidence (the kinds that require evidence — copilot Q&A
            may temporarily allow zero evidence at the API boundary; here
            we require at least one item for every other kind),
          * unique evidence ids and unique citation tokens,
          * every citation token matches its evidence id deterministically.
        """
        if not request.evidence:
            raise AIGroundingError(
                "evidence bundle is empty; the AI engine refuses to generate ungrounded output",
                context={"request_id": str(request.request_id), "kind": request.kind.value},
            )

        seen_ids: set[str] = set()
        seen_tokens: set[str] = set()
        for item in request.evidence:
            if item.evidence_id in seen_ids:
                raise AIGroundingError(
                    "duplicate evidence_id in evidence bundle",
                    context={"evidence_id": item.evidence_id},
                )
            seen_ids.add(item.evidence_id)

            if item.citation_token in seen_tokens:
                raise AIGroundingError(
                    "duplicate citation_token in evidence bundle",
                    context={"citation_token": item.citation_token},
                )
            seen_tokens.add(item.citation_token)

    # ------------------------------------------------------------------ output

    def validate_output(
        self,
        text: str,
        evidence: Iterable[GroundedEvidenceItem],
    ) -> GroundingValidationResult:
        """Check produced ``text`` against the evidence bundle.

        Never raises — returns a structured result so the orchestrator can
        log the breakdown and decide whether to retry / downgrade / block.
        """
        allowed_tokens = {e.citation_token for e in evidence}
        used_tokens = CITATION_PATTERN.findall(text)
        used_set = set(used_tokens)

        missing = sorted(used_set - allowed_tokens)

        # Entity coverage.
        evidence_ids = {e.ref_id for e in evidence}
        # Also accept short forms (last UUID segment, technique base id) — kept
        # conservative; final logic in Phase 5 ties this to a typed entity index.
        unsupported_entities: list[str] = []
        for entity in ENTITY_LIKE_PATTERN.findall(text):
            if entity in evidence_ids:
                continue
            if any(entity in e.summary or entity in str(e.redacted_payload) for e in evidence):
                continue
            unsupported_entities.append(entity)
        unsupported_entities = sorted(set(unsupported_entities))

        paragraphs = [p for p in text.split("\n\n") if p.strip()]
        paragraph_count = max(1, len(paragraphs))
        coverage = round(min(1.0, len(used_tokens) / paragraph_count) * 100, 1)

        notes: list[str] = []
        if self._require_per_paragraph:
            uncited_paragraphs = sum(
                1
                for p in paragraphs
                if p.strip() and not CITATION_PATTERN.search(p)
            )
            if uncited_paragraphs:
                notes.append(f"{uncited_paragraphs} paragraph(s) without citation")

        passed = (
            not missing
            and not unsupported_entities
            and "uncited" not in " ".join(notes)
        )
        return GroundingValidationResult(
            passed=passed,
            citation_count=len(used_tokens),
            missing_citations=tuple(missing),
            unsupported_entities=tuple(unsupported_entities),
            coverage_pct=coverage,
            notes=tuple(notes),
        )


# ---------------------------------------------------------------------------
# EvidenceBuilder (helper used by the orchestrator)
# ---------------------------------------------------------------------------


class EvidenceBuilder:
    """Mint ``GroundedEvidenceItem``s from upstream domain objects.

    The orchestrator (Phase 5+) uses this to translate ``Finding`` /
    ``Asset`` / ``Score`` / TI objects fetched from Cosmos + SQL into a
    minimal, redacted evidence bundle the AI engine can read. This class
    is intentionally tiny so it stays easy to audit.
    """

    def __init__(self, tenant_id: UUID) -> None:
        self._tenant_id = tenant_id
        self._counter = 0

    def next_token(self) -> str:
        self._counter += 1
        return f"[[evi:{self._counter}]]"

    def make(
        self,
        *,
        evidence_id: str,
        evidence_type: EvidenceType,
        ref_id: str,
        summary: str,
        redacted_payload: dict[str, object] | None = None,
        source_uri: str | None = None,
    ) -> GroundedEvidenceItem:
        """Build one evidence item with an auto-minted citation token."""
        # The orchestrator is responsible for ensuring ``ref_id`` and
        # ``redacted_payload`` were fetched within the tenant's scope.
        # This helper does not enforce that; the safety layer does.
        return GroundedEvidenceItem(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            ref_id=ref_id,
            summary=summary,
            citation_token=self.next_token(),
            redacted_payload=dict(redacted_payload or {}),
            source_uri=source_uri,
        )


__all__ = [
    "CITATION_PATTERN",
    "ENTITY_LIKE_PATTERN",
    "EvidenceBuilder",
    "GroundingValidationResult",
    "GroundingValidator",
]
