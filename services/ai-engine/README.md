# services/ai-engine

Skeleton for the **AI Analysis Engine**. No Azure OpenAI calls implemented yet.

## Purpose

Translate structured findings, scores, frameworks, and threat-intel correlations into:

- Executive narrative ("here's what matters and why").
- Plain-language finding explanations with business impact.
- Drafted remediations (Azure CLI / PowerShell / Microsoft Graph / Azure Policy snippets) — *suggested* only, never auto-executed in default mode.
- Campaign briefings ("this campaign matters to you because…").
- Auditor-grade compliance evidence prose.
- Conversational copilot answers, **grounded in the tenant's own data via RAG**, with mandatory citations.

Importantly, the AI engine **never invents findings**. It only summarizes structured inputs produced by the scanner, compliance, risk, and TI engines. See `docs/ARCHITECTURE.md` § 8 and `docs/SECURITY_MODEL.md` § 11.

## Future Responsibilities

- **Prompt library** (`ai_engine.prompts`): versioned, peer-reviewed templates per use case.
- **Prompt router** (`ai_engine.router`): selects template + model deployment.
- **Azure OpenAI client** (`ai_engine.client`): MI auth, retry, token accounting, content filtering.
- **RAG retrieval** (`ai_engine.rag`): per-tenant Azure AI Search index; hybrid lexical + vector queries.
- **Output guards** (`ai_engine.guards`): JSON schema validation, PII redaction, prompt-injection mitigations, citation enforcement.
- **Audit** (`ai_engine.audit`): redacted prompt + response logged per tenant with TTL.

## Safety Posture

- No training on customer data (contractual + technical via Azure OpenAI).
- Tenant-scoped RAG: prompts retrieve only from the requesting tenant's index.
- System-prompt isolation and instruction hierarchies.
- Tool-use outputs JSON-schema validated before any execution.
- Per-tenant token quotas; soft-blocks with notification on overage.
- Full prompt + response audit (PII-redacted) with TTL.

## Inputs (planned)

- Service Bus topic `ai.summarize.requested` (from API, reporting, notification).
- Synchronous API path: `POST /api/v1/copilot/messages` (streaming).
- Reference materials via the per-tenant AI Search index.

## Outputs (planned)

- AI artifacts persisted in Cosmos DB (`ai_prompts` container; see `docs/SCHEMA_DESIGN.md` § 9).
- Streamed copilot responses back to the API.
- Optional emission of `report.generate.requested` after composing a long-form artifact.

## Local Development (planned)

```bash
cd services/ai-engine
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m ai_engine.main --once
```

No Azure OpenAI calls in this skeleton. No API keys read.

## Status

Skeleton only. Real Azure OpenAI + RAG + copilot land in Phase 5 (`docs/ROADMAP.md`). MVP narrative summarization is a Phase 1 placeholder using a single template.
