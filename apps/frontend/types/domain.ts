// AzureLens — frontend domain types
//
// TypeScript shapes that mirror the v1 API responses (Phase 7 demo mode).
// Keep these in sync with `apps/api/app/models/*` and `apps/api/app/demo/service.py`.
// Phase 1+ will generate this file from the OpenAPI snapshot in
// `packages/contracts/`. Until then, hand-edited.

// ---------------------------------------------------------------------------
// Enums (string-literal unions)
// ---------------------------------------------------------------------------

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type ScoreBand =
  | "critical"
  | "weak"
  | "moderate"
  | "strong"
  | "excellent";

export type ScoreKind =
  | "overall"
  | "identity"
  | "azure_exposure"
  | "device"
  | "threat_exposure"
  | "m365_compliance";

export type FindingStatus =
  | "open"
  | "acknowledged"
  | "suppressed"
  | "remediated"
  | "false_positive";

export type Exploitability = "none" | "theoretical" | "poc" | "active";

export type ExposureLevel = "internal" | "partner" | "public" | "unknown";

export type Criticality = "low" | "moderate" | "high" | "critical";

export type CloudProvider =
  | "azure"
  | "m365"
  | "entra_id"
  | "intune"
  | "defender_xdr"
  | "purview"
  | "aws"
  | "gcp";

export type ScanStatus =
  | "requested"
  | "queued"
  | "running"
  | "completed"
  | "partial"
  | "failed"
  | "cancelled";

export type ScanKind =
  | "azure"
  | "m365"
  | "intune"
  | "defender"
  | "sentinel"
  | "purview"
  | "full";

export type ScanTriggerType =
  | "bootstrap"
  | "scheduled"
  | "incremental"
  | "on_demand"
  | "targeted";

export type ComplianceFramework =
  | "cis_azure"
  | "mcsb"
  | "nist_csf"
  | "nist_800_53"
  | "iso_27001"
  | "soc2"
  | "gdpr"
  | "zero_trust"
  | "azure_waf"
  | "m365_baseline"
  | "cis_m365"
  | "hipaa"
  | "pci_dss";

export type RemediationStatus =
  | "not_started"
  | "suggested"
  | "requested"
  | "approved"
  | "executing"
  | "succeeded"
  | "failed"
  | "rolled_back";

export type RemediationStepKind =
  | "azure_cli"
  | "powershell"
  | "ms_graph"
  | "azure_policy"
  | "doc_link"
  | "manual";

// ---------------------------------------------------------------------------
// Tenant
// ---------------------------------------------------------------------------

export interface TenantSummary {
  id: string;
  display_name: string;
  tier: "free" | "pro" | "enterprise" | "customer_hosted";
  status: "provisioning" | "active" | "suspended" | "offboarding";
  data_residency: string;
}

// ---------------------------------------------------------------------------
// Score
// ---------------------------------------------------------------------------

export interface Score {
  tenant_id: string;
  score_kind: ScoreKind;
  value: number;
  band: ScoreBand;
  contributing_finding_ids: string[];
  calculated_at: string;
}

export interface ScoreOverview {
  overall: Score;
  domains: Score[];
}

export interface ScoreHistoryPoint {
  recorded_at: string;
  value: number;
}

export interface ScoreHistory {
  score_kind: ScoreKind;
  points: ScoreHistoryPoint[];
}

// ---------------------------------------------------------------------------
// Finding
// ---------------------------------------------------------------------------

export interface FindingSummary {
  id: string;
  tenant_id: string;
  title: string;
  finding_type: string;
  severity: Severity;
  status: FindingStatus;
  risk_score: number;
  asset_id: string;
  last_seen_at: string;
}

export interface Finding {
  id: string;
  tenant_id: string;
  finding_type: string;
  title: string;
  description: string;
  severity: Severity;
  status: FindingStatus;
  exploitability: Exploitability;
  asset_id: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
  framework_mappings?: Record<string, unknown>;
  risk_score: number;
  campaign_links?: CampaignLinkRef[];
  remediation?: RemediationSummaryRef | null;
  first_seen_at: string;
  last_seen_at: string;
  last_evaluated_at: string;
  source_scanner: string;
}

export interface CampaignLinkRef {
  campaign_id: string;
  name: string;
  source: string;
  confidence: number;
}

export interface RemediationSummaryRef {
  template_id: string;
  title: string;
  estimated_minutes: number | null;
  risk_reduction_estimate: number | null;
  docs_url: string | null;
}

// ---------------------------------------------------------------------------
// Asset
// ---------------------------------------------------------------------------

export interface AssetSummary {
  id: string;
  tenant_id: string;
  asset_kind: string;
  provider: CloudProvider;
  display_name: string | null;
  exposure: ExposureLevel;
  criticality: Criticality;
  open_finding_count: number;
  highest_finding_severity: Severity | null;
}

// ---------------------------------------------------------------------------
// Threat intel
// ---------------------------------------------------------------------------

export interface CampaignExposureSummary {
  tenant_id: string;
  campaign_id: string;
  campaign_name: string;
  affected_asset_count: number;
  highest_severity: Severity;
  correlation_dimensions: string[];
  last_observed_at: string;
}

export interface ThreatExposureSummary {
  active_campaigns: CampaignExposureSummary[];
  kev_cve_count: number;
  mitre_techniques_observed: string[];
  correlation_count: number;
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

export interface ComplianceFrameworkSummary {
  framework: ComplianceFramework;
  version: string;
  score: number;
  non_compliant: number;
  partially_compliant: number;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export interface ScanSummary {
  tenant_id: string;
  id: string;
  kinds: ScanKind[];
  trigger_type: ScanTriggerType;
  status: ScanStatus;
  requested_at: string;
  started_at: string | null;
  completed_at: string | null;
  partitions_total: number | null;
  partitions_completed: number;
  findings_produced: number;
  error_summary: string | null;
}

export interface RecentScanSummary {
  scan_id: string | null;
  kinds: ScanKind[];
  status: ScanStatus | null;
  requested_at: string | null;
  completed_at: string | null;
  findings_produced: number;
}

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export interface RemediationAction {
  tenant_id: string;
  id: string;
  finding_id: string;
  template_id: string;
  status: RemediationStatus;
  requested_by: string;
  approved_by: string | null;
  requested_at: string;
  started_at: string | null;
  ended_at: string | null;
  diff_before: Record<string, unknown>;
  diff_after: Record<string, unknown>;
  error_summary: string | null;
}

export interface RemediationStep {
  kind: RemediationStepKind;
  title: string;
  code: string | null;
  docs_url: string | null;
}

export interface RemediationTemplate {
  template_id: string;
  title: string;
  version: number;
  applies_to_finding_types: string[];
  steps: RemediationStep[];
  rollback_steps: RemediationStep[];
  estimated_minutes: number | null;
  risk_reduction_estimate: number | null;
}

export interface RemediationRoadmapSummary {
  open: number;
  suggested: number;
  requested: number;
  approved: number;
  in_progress: number;
  succeeded: number;
  failed: number;
  next_actions: RemediationAction[];
}

// ---------------------------------------------------------------------------
// Dashboard composite
// ---------------------------------------------------------------------------

export interface OverallScoreSummary {
  score_kind: "overall";
  value: number;
  band: ScoreBand | string;
  calculated_at: string;
  delta_7d: number;
}

export interface DomainScoreSummary {
  score_kind: ScoreKind;
  value: number;
  band: ScoreBand | string;
}

export interface TopRiskItem {
  finding_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  asset_id: string;
  finding_type: string;
}

export interface DashboardSummary {
  tenant_id: string;
  tenant_name: string;
  overall: OverallScoreSummary;
  domain_scores: DomainScoreSummary[];
  top_risks: TopRiskItem[];
  threat_exposure: ThreatExposureSummary;
  compliance_summary: ComplianceFrameworkSummary[];
  recent_scan: RecentScanSummary;
  remediation_roadmap: RemediationRoadmapSummary;
  generated_at: string;
}
