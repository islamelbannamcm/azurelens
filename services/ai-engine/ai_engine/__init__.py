"""AzureLens AI Analysis engine.

Logical subpackages (added in later phases):
  - ai_engine.prompts   : versioned prompt templates (executive, finding, remediation, copilot)
  - ai_engine.router    : template + model deployment selection
  - ai_engine.client    : Azure OpenAI client wrapper (Managed Identity)
  - ai_engine.rag       : retrieval over the per-tenant Azure AI Search index
  - ai_engine.guards    : output schema validation, PII redaction, injection mitigations
  - ai_engine.audit     : redacted prompt + response logging
"""
