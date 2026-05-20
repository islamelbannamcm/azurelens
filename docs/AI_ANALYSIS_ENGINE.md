# AzureLens — AI Analysis Engine

How AzureLens uses Azure OpenAI to turn structured posture, compliance, scoring, and threat-intelligence data into executive-grade narrative, plain-language finding explanations, audience-shaped remediation guidance, campaign briefings, auditor evidence summaries, and a conversational copilot — **without ever generating findings or numbers from a language model**.

> Foundation note: Phase 6 introduces the contracts, prompt templates, safety controls, grounding enforcement, remediation advisor, and report generator. Real Azure OpenAI inference is wired in Phase 5 — until then, every output in this package is produced by deterministic code paths. See `docs/PROMPT_SAFETY_MODEL.md` for the safety policy this engine enforces.

---

## 1. Hard architectural rules (read this first)

1. **Deterministic source of truth.** Scores, findings, frameworks, and TI correlations are produced by the scanner, compliance, risk, and TI services. The AI engine never produces a number or a finding. It rewrites and summarizes.
2. **Evidence-only generation.** Every AI output cites a `[[evi:N]]` token that maps to a `GroundedEvidenceItem` the orchestrator pre-built for the request. Any output that fails citation validation is blocked.
3. **Tenant isolation.** Every analysis call carries `tenant_id`; per-tenant RAG indexes and grounding inputs are filtered to that tenant. Cross-tenant references are a P0 block.
4. **No autonomous actions.** Remediation outputs are always *suggestions* with explicit `ApprovalRequirement` markers. The AI cannot call tools or invoke remediation directly.
5. **Auditable.** Every prompt, response, safety decision, and grounding result is captured in the `ai_prompts` Cosmos container (PII-redacted) with TTL.

---

## 2. Module map

```
services/ai-engine/ai_engine/
├── __init__.py                    public re-exports
├── contracts.py                   Pydantic v2 request/response/structured outputs/safety/report
├── errors.py                      AIEngineError hierarchy
├── safety.py                      SafetyEvaluator — deterministic rules (no LLM)
├── grounding.py                   GroundingValidator + EvidenceBuilder
├── prompt_templates.py            6 immutable prompt templates with shared safety preamble
├── remediation_advisor.py         deterministic remediation library + AI-enhance hook
└── report_generator.py            deterministic report sections + AI-enhance hooks
```

---

## 3. End-to-end flow

```
incoming request (API / Service Bus)
        │
        ▼
orchestrator
  ├─► build GroundedEvidenceItem[] from tenant-scoped Cosmos/SQL queries
  │     (EvidenceBuilder mints citation tokens; PII redacted before embedding)
  ├─► GroundingValidator.validate_request(...)        ── raise on contract violation
  ├─► SafetyEvaluator.evaluate_inputs(request)        ── BLOCK / REDACT / ALLOW
  │      (in Phase 5 the result is merged with Azure AI Content Safety
  │       Prompt Shield using the strictest-of-two rule)
  ▼
prompt template selection + rendering
  ├─► get_template(kind→template_id)
  ├─► render `system_prompt + user_prompt_template` with evidence + parameters
  ▼
LLM call (Phase 5+)
  ├─► Azure OpenAI deployment (model + region + PTU/PAYG)
  ├─► tools/functions disabled by default; JSON-schema validated when on
  ▼
SafetyEvaluator.evaluate_output(text, request)
  ├─► strip residual PII / secrets (rule-based)
  ├─► reject ungrounded claims, cross-tenant references, missing citations
  ├─► merge with Azure AI Content Safety output moderation (Phase 5+)
  ▼
GroundingValidator.validate_output(text, evidence)
  ├─► citation coverage, entity-drift checks
  ▼
AIAnalysisResponse (structured + markdown + citations + safety_decision)
  ├─► persisted as AIAuditEntry (redacted) → ai_prompts container
  ├─► returned via API / event
```

If any step blocks: the user-facing response is a safe error; the orchestrator records the full structured detail in the audit pipeline.

---

## 4. Grounding (the headline invariant)

`grounding.py` enforces:

- **No-evidence-no-output.** A request whose `evidence[]` is empty (for kinds that require it) is rejected.
- **Unique evidence ids and citation tokens.** Prevents accidental aliasing.
- **Citation coverage.** Every paragraph in produced output must contain at least one `[[evi:N]]` token. Outputs without any citations are blocked.
- **Allowlisted tokens.** Outputs may only cite tokens that exist in the request's evidence.
- **Entity-drift detection.** Mentions of UUIDs, `sha256:…` asset ids, CVE ids, or MITRE technique ids that aren't represented in the evidence trigger a block.

The orchestrator builds evidence via `EvidenceBuilder.make(...)` — a tiny helper that mints citation tokens and a redacted payload. Every `GroundedEvidenceItem` is small (≤ ~2KB) and contains only what the analysis kind needs.

---

## 5. Prompt templates

Six built-in immutable templates ship with this branch. Each carries a stable id + version, the shared `SAFETY_PREAMBLE`, a kind-specific `system_prompt`, a `user_prompt_template`, an output schema (where applicable), a temperature, and a required-evidence-types list.

| Template id | Kind | Audience | Required evidence |
|---|---|---|---|
| `exec.summary.v1`        | executive summary    | executive  | score, finding, ti_campaign |
| `finding.explain.v1`     | finding explanation  | technical  | finding, asset (+ MITRE / control) |
| `finding.remediate.v1`   | remediation guidance | technical  | finding, asset, remediation_template |
| `compliance.impact.v1`   | compliance impact    | compliance | finding, framework_control |
| `campaign.brief.v1`      | campaign exposure    | SOC analyst | ti_campaign, ti_indicator, finding |
| `audit.evidence.v1`      | auditor evidence     | auditor    | finding, framework_control |

Templates are **versioned and immutable**. A new tuning round produces `v2`; both versions remain resolvable so historical audit logs continue to render identically.

---

## 6. Two-phase generation pattern

Both `RemediationAdvisor` and `ReportGenerator` ship a deterministic baseline today and a clearly-marked AI-enhancement step for Phase 5:

| Component | Deterministic now | AI later (preserved invariants) |
|---|---|---|
| `RemediationAdvisor.recommend` | Looks up `RemediationTemplate` by `finding_type`; produces `RemediationRecommendation` with steps, prereqs, rollback, approval. | AI rewrites only `title`, `summary`, per-step `description`. Steps' `kind`, `code`, `approval_required`, order, and rollback are preserved verbatim. |
| `ReportGenerator.build` | Builds Markdown sections from `ReportInputs` (scores, findings, campaigns). | AI rewrites the prose overview + per-section narratives. Numbers, ids, table rows, and citations are preserved exactly. |

If AI is unavailable, customers still get correct, evidence-cited, executable output — just in default-template language. The `ai_enhanced: bool` flag on every section / recommendation surfaces which path produced the prose.

---

## 7. Safety controls

`safety.py` runs deterministic, regex-based checks on both prompt inputs and produced outputs:

- Prompt-injection signatures (system-prompt override patterns, jailbreak markers).
- Secret signatures (API keys, AWS access keys, Azure storage keys, private-key blocks, JWTs, GitHub tokens).
- PII residuals (email, phone, SSN-shaped, credit-card-shaped, IPv4) — orchestrator redacts before evidence is built; this is defense in depth.
- Cross-tenant references (`tenant_id=<UUID>` other than the requesting tenant) → BLOCK.
- Hallucination markers (`probably`, `I think`, `in my training data`, …) → REDACT.
- Citation coverage on outputs.

Outcomes are `ALLOW`, `REDACT`, or `BLOCK`. The orchestrator honors the strictest of (this layer, Azure AI Content Safety Prompt Shield, Azure AI Content Safety output moderation). See `docs/PROMPT_SAFETY_MODEL.md`.

---

## 8. Model routing & deployment

Phase 5 introduces explicit routing:

| Use case | Model class | Notes |
|---|---|---|
| Executive narrative | larger reasoning model | low temperature (0.3 – 0.4) |
| Finding explanation | smaller chat model | very low temperature (0.1 – 0.2) |
| Remediation rewrite | smaller chat model | temperature 0.2 |
| Copilot Q&A | larger reasoning model | RAG-only, citations enforced |
| Embeddings (RAG) | `text-embedding-3-large` | one index per tenant in Enterprise tier |
| Auditor evidence | smaller chat model | temperature 0.1 |

Each deployment is identified by `ModelDeploymentRef(deployment_name, api_version, region, ptu)`:

- **Region**: chosen at deployment time to match the tenant's `data_residency`. The orchestrator never crosses geos.
- **PTU vs PAYG**: Enterprise tier may pin a Provisioned-Throughput-Unit deployment for predictable latency. Pro tier uses pay-as-you-go.
- **Failover**: a secondary deployment in the paired region is used only when the primary is unavailable; the choice is recorded in the audit entry.

---

## 9. RAG (Phase 5+)

- One Azure AI Search index per tenant (Enterprise) or per-tenant filter (Pro).
- Indexed sources:
  - Last N normalized findings (and their explainability reasons).
  - Relevant TI objects post-correlation.
  - Framework reference packs (shared but tagged).
  - Remediation playbook library.
- Embeddings: `text-embedding-3-large`; structured-first chunking (one chunk per finding / control / campaign / playbook) + supplementary prose chunks.
- Retrieval is always filtered to `tenant_id`. Cross-tenant retrieval is impossible at the SDK call layer.

---

## 10. Audit

Every analysis call writes an `AIAuditEntry`:

- `prompt_redacted` / `response_redacted` — PII-redacted by the safety layer.
- `template_id` + `template_version` for reproducibility.
- `model_deployment` so the exact LLM + region + PTU is recorded.
- `safety_decision` (full structured outcome).
- `correlation_id` (W3C `traceparent`) for end-to-end tracing.
- `tokens_in/out`, `latency_ms` for cost + perf telemetry.
- `ttl_days` per tenant policy (default 365).

Audit entries live in Cosmos `ai_prompts` (partition by tenant_id) and are mirrored to Log Analytics for queryable analytics. Customers in Enterprise tier may stream this audit to their own Sentinel workspace.

---

## 11. Evaluation harness (Phase 5+)

Before any prompt template's version is bumped to `v2`:

1. **Snapshot tests** against ≥ 50 hand-curated evidence bundles per template.
2. **Blind reviewer evaluation** — three reviewers compare new vs old paragraph quality (executive narrative target: ≥ 80% preference for the new version).
3. **Red-team prompt-injection suite** — 200+ adversarial inputs that should all produce `REFUSED:PROMPT_OVERRIDE` or `REFUSED:SAFETY` outputs. Zero escapes allowed.
4. **Cross-tenant leak test** — synthetic evidence containing other tenants' identifiers must always be blocked.
5. **Citation completeness** — across the eval set, the grounding validator must accept ≥ 99% of outputs without retries.
6. **Latency / cost regression** — P95 latency and token spend may not regress more than 10% without explicit sign-off.

TODO(phase-5): implement the harness under `tests/ai_eval/`; gate template version bumps in CI on its results.

---

## 12. Approval workflows

The AI engine never executes. Remediation outputs route through Logic Apps Standard (Phase 4) for human approval:

- `none` → informational; no gate.
- `single_approver` → one named approver from the tenant's SecurityAdmin / IT-manager group.
- `dual_control` → two distinct approvers from disjoint groups; default for identity-touching changes.
- `change_advisory` → routes through the customer's change-advisory board (ServiceNow / Jira integration, Phase 9).

The approval requirement is determined deterministically by `RemediationAdvisor` and is *immutable* through the AI rewrite step.

---

## 13. Operational properties

- **Availability**: AI is a best-effort enhancement. If the LLM is down, every component degrades to its deterministic baseline.
- **Cost guardrails**: per-tenant daily token budget; per-call max output tokens; cost telemetry per template + audience.
- **Latency target**: P95 ≤ 2 s for `finding.explain.v1`; ≤ 4 s for `exec.summary.v1`; ≤ 1 s P95 for copilot streaming first-token.
- **Idempotency**: same `(template_id, template_version, evidence)` → identical structured output keys (the prose may differ within the temperature budget).

---

## 14. Roadmap

- **Phase 5** — wire Azure OpenAI (model routing, RAG, content safety), implement the evaluation harness, light up `exec.summary.v1` + `finding.explain.v1` first.
- **Phase 5.5** — `finding.remediate.v1` AI rewriting (preserves steps; rewrites prose).
- **Phase 5.5** — copilot endpoint with citation enforcement.
- **Phase 6** — `compliance.impact.v1`, `campaign.brief.v1`, `audit.evidence.v1`.
- **Phase 7** — multi-tenant PTU sizing; per-region failover.
- **Phase 8** — counterfactual narrative ("if you fix X, identity score lifts by Y").
- **Phase 9** — partner / marketplace prompt templates (signed + versioned).

See `docs/ROADMAP.md`.
