"""AzureLens Risk Scoring engine.

Logical subpackages (added in later phases):
  - risk_engine.policy     : versioned scoring policy loader (per-tenant overrides)
  - risk_engine.factors    : exploitability, exposure, business impact, compliance, campaign
  - risk_engine.scorer     : pure-function score(finding, asset, hits, policy) -> Score
  - risk_engine.aggregator : per-domain and per-tenant rollups
"""
