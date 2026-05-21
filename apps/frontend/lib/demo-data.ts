// Phase 11 — deterministic fallback demo data shared by every route.
//
// Extracted from the inlined `FALLBACK_DASHBOARD` previously in
// `app/page.tsx`. Mirrors `apps/api/app/demo/service.py`. Used only when the
// real API is unreachable so the dashboard, findings, scans, etc. still
// render (CI / design preview / local frontend in isolation).
//
// Keep this in sync with the backend demo fixture; Phase 1+ should generate
// it from the OpenAPI snapshot in `packages/contracts/`.

import type {
  AssetSummary,
  CampaignExposureSummary,
  ComplianceFrameworkSummary,
  DashboardSummary,
  FindingSummary,
  RemediationAction,
  RemediationRoadmapSummary,
  ScanSummary,
  ThreatExposureSummary,
} from "@/types/domain";

const TENANT_ID = "00000000-0000-0000-0000-000000000001";
const TENANT_NAME = "Contoso Demo";
const NOW = "2026-05-20T10:00:00Z";

export const DEMO_DASHBOARD: DashboardSummary = {
  tenant_id: TENANT_ID,
  tenant_name: TENANT_NAME,
  overall: {
    score_kind: "overall",
    value: 64,
    band: "moderate",
    calculated_at: NOW,
    delta_7d: 5,
  },
  domain_scores: [
    { score_kind: "identity",         value: 58, band: "weak" },
    { score_kind: "azure_exposure",   value: 52, band: "weak" },
    { score_kind: "device",           value: 71, band: "moderate" },
    { score_kind: "threat_exposure",  value: 60, band: "moderate" },
    { score_kind: "m365_compliance",  value: 79, band: "strong" },
  ],
  top_risks: [
    {
      finding_id: "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      title: "Privileged identity without MFA",
      severity: "critical",
      risk_score: 92,
      asset_id: "sha256:asset-user-admin",
      finding_type: "identity.mfa.privileged.missing",
    },
    {
      finding_id: "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      title: "RDP exposed to the public internet",
      severity: "critical",
      risk_score: 88,
      asset_id: "sha256:asset-vm-prod-web-01",
      finding_type: "azure.network.rdp_public_exposed",
    },
    {
      finding_id: "aaaaaaac-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      title: "Affected by an actively exploited CVE (CISA KEV)",
      severity: "critical",
      risk_score: 84,
      asset_id: "sha256:asset-vm-prod-web-01",
      finding_type: "threat.kev_cve.affected_software",
    },
    {
      finding_id: "aaaaaaad-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      title: "Active Akira ransomware campaign correlates to this tenant",
      severity: "high",
      risk_score: 78,
      asset_id: "sha256:asset-vm-prod-web-01",
      finding_type: "threat.campaign.correlation",
    },
    {
      finding_id: "aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      title: "Storage account allows public blob access",
      severity: "high",
      risk_score: 76,
      asset_id: "sha256:asset-stprodassets01",
      finding_type: "azure.storage.public_access",
    },
  ],
  threat_exposure: {
    active_campaigns: [
      {
        tenant_id: TENANT_ID,
        campaign_id: "campaign::akira-rdp-2026q2",
        campaign_name: "Akira ransomware — RDP brute-force wave",
        affected_asset_count: 1,
        highest_severity: "critical",
        correlation_dimensions: ["technique_to_finding"],
        last_observed_at: NOW,
      },
      {
        tenant_id: TENANT_ID,
        campaign_id: "campaign::storm-1234-phishing-2026q2",
        campaign_name: "Storm-1234 — credential phishing wave",
        affected_asset_count: 1,
        highest_severity: "high",
        correlation_dimensions: ["sector_alignment"],
        last_observed_at: "2026-05-19T12:00:00Z",
      },
    ],
    kev_cve_count: 1,
    mitre_techniques_observed: [
      "T1078", "T1078.004", "T1098", "T1110.003", "T1133",
      "T1190", "T1486", "T1530", "T1556.006", "T1562.008", "T1567",
    ],
    correlation_count: 2,
  },
  compliance_summary: [
    { framework: "cis_azure", version: "2.1.0", score: 68, non_compliant: 20, partially_compliant: 22 },
    { framework: "mcsb",      version: "1.0",   score: 71, non_compliant: 12, partially_compliant: 18 },
    { framework: "nist_csf",  version: "2.0",   score: 72, non_compliant: 12, partially_compliant: 22 },
    { framework: "iso_27001", version: "2022",  score: 74, non_compliant: 8,  partially_compliant: 20 },
    { framework: "soc2",      version: "2017",  score: 79, non_compliant: 2,  partially_compliant: 6 },
    { framework: "gdpr",      version: "2018",  score: 81, non_compliant: 1,  partially_compliant: 4 },
  ],
  recent_scan: {
    scan_id: "11111111-2222-3333-4444-555555555555",
    kinds: ["full"],
    status: "completed",
    requested_at: "2026-05-20T09:00:00Z",
    completed_at: NOW,
    findings_produced: 12,
  },
  remediation_roadmap: {
    open: 5,
    suggested: 1,
    requested: 1,
    approved: 1,
    in_progress: 0,
    succeeded: 1,
    failed: 0,
    next_actions: [
      {
        tenant_id: TENANT_ID,
        id: "dddd0001-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.identity.enforce_mfa_privileged.v2",
        status: "suggested",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: null,
        requested_at: "2026-05-18T12:00:00Z",
        started_at: null, ended_at: null,
        diff_before: {}, diff_after: {},
        error_summary: null,
      },
      {
        tenant_id: TENANT_ID,
        id: "dddd0002-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.azure.nsg.restrict_rdp.v1",
        status: "requested",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: null,
        requested_at: "2026-05-19T12:00:00Z",
        started_at: null, ended_at: null,
        diff_before: {}, diff_after: {},
        error_summary: null,
      },
      {
        tenant_id: TENANT_ID,
        id: "dddd0003-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.azure.storage.disable_public.v1",
        status: "approved",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        requested_at: "2026-05-19T16:00:00Z",
        started_at: null, ended_at: null,
        diff_before: {}, diff_after: {},
        error_summary: null,
      },
    ],
  },
  generated_at: "2026-05-20T12:00:00Z",
};

// ─── Per-route demo collections (derived from the same tenant fixture) ───

export const DEMO_FINDINGS: FindingSummary[] = [
  {
    id: "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Privileged identity without MFA",
    finding_type: "identity.mfa.privileged.missing",
    severity: "critical",
    status: "open",
    risk_score: 92,
    asset_id: "sha256:asset-user-admin",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "RDP exposed to the public internet",
    finding_type: "azure.network.rdp_public_exposed",
    severity: "critical",
    status: "open",
    risk_score: 88,
    asset_id: "sha256:asset-vm-prod-web-01",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaac-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Affected by an actively exploited CVE (CISA KEV)",
    finding_type: "threat.kev_cve.affected_software",
    severity: "critical",
    status: "open",
    risk_score: 84,
    asset_id: "sha256:asset-vm-prod-web-01",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaad-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Active Akira ransomware campaign correlates to this tenant",
    finding_type: "threat.campaign.correlation",
    severity: "high",
    status: "open",
    risk_score: 78,
    asset_id: "sha256:asset-vm-prod-web-01",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Storage account allows public blob access",
    finding_type: "azure.storage.public_access",
    severity: "high",
    status: "open",
    risk_score: 76,
    asset_id: "sha256:asset-stprodassets01",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaa6-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Legacy authentication permitted",
    finding_type: "identity.legacy_auth.enabled",
    severity: "high",
    status: "open",
    risk_score: 72,
    asset_id: "sha256:asset-tenant-policy",
    last_seen_at: NOW,
  },
  {
    id: "aaaaaaa7-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Conditional Access policy missing on privileged users",
    finding_type: "identity.ca.privileged.missing",
    severity: "medium",
    status: "acknowledged",
    risk_score: 58,
    asset_id: "sha256:asset-tenant-policy",
    last_seen_at: "2026-05-19T08:00:00Z",
  },
  {
    id: "aaaaaaa8-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Sensitivity label policy not assigned to finance group",
    finding_type: "m365.purview.label.unassigned",
    severity: "medium",
    status: "open",
    risk_score: 51,
    asset_id: "sha256:asset-group-finance",
    last_seen_at: "2026-05-19T08:00:00Z",
  },
  {
    id: "aaaaaaa9-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    tenant_id: TENANT_ID,
    title: "Devices not onboarded to Defender for Endpoint",
    finding_type: "intune.defender.onboarding.missing",
    severity: "low",
    status: "open",
    risk_score: 34,
    asset_id: "sha256:asset-device-pool",
    last_seen_at: "2026-05-19T08:00:00Z",
  },
];

export const DEMO_CAMPAIGNS: CampaignExposureSummary[] =
  DEMO_DASHBOARD.threat_exposure.active_campaigns;

export const DEMO_COMPLIANCE: ComplianceFrameworkSummary[] =
  DEMO_DASHBOARD.compliance_summary;

export const DEMO_THREAT_EXPOSURE: ThreatExposureSummary =
  DEMO_DASHBOARD.threat_exposure;

export const DEMO_REMEDIATION_ROADMAP: RemediationRoadmapSummary =
  DEMO_DASHBOARD.remediation_roadmap;

export const DEMO_REMEDIATIONS: RemediationAction[] =
  DEMO_DASHBOARD.remediation_roadmap.next_actions;

export const DEMO_SCANS: ScanSummary[] = [
  {
    tenant_id: TENANT_ID,
    id: "11111111-2222-3333-4444-555555555555",
    kinds: ["full"],
    trigger_type: "scheduled",
    status: "completed",
    requested_at: "2026-05-20T09:00:00Z",
    started_at: "2026-05-20T09:00:30Z",
    completed_at: NOW,
    partitions_total: 8,
    partitions_completed: 8,
    findings_produced: 12,
    error_summary: null,
  },
  {
    tenant_id: TENANT_ID,
    id: "22222222-2222-3333-4444-555555555555",
    kinds: ["azure"],
    trigger_type: "incremental",
    status: "completed",
    requested_at: "2026-05-19T21:00:00Z",
    started_at: "2026-05-19T21:00:18Z",
    completed_at: "2026-05-19T21:11:42Z",
    partitions_total: 3,
    partitions_completed: 3,
    findings_produced: 2,
    error_summary: null,
  },
  {
    tenant_id: TENANT_ID,
    id: "33333333-2222-3333-4444-555555555555",
    kinds: ["m365", "defender"],
    trigger_type: "on_demand",
    status: "partial",
    requested_at: "2026-05-19T15:00:00Z",
    started_at: "2026-05-19T15:00:12Z",
    completed_at: "2026-05-19T15:09:55Z",
    partitions_total: 5,
    partitions_completed: 4,
    findings_produced: 4,
    error_summary: "Graph throttling on /security/secureScores; retry queued.",
  },
];

export const DEMO_ASSETS: AssetSummary[] = [
  {
    id: "sha256:asset-vm-prod-web-01",
    tenant_id: TENANT_ID,
    asset_kind: "azure.compute.vm",
    provider: "azure",
    display_name: "vm-prod-web-01",
    exposure: "public",
    criticality: "critical",
    open_finding_count: 3,
    highest_finding_severity: "critical",
  },
  {
    id: "sha256:asset-stprodassets01",
    tenant_id: TENANT_ID,
    asset_kind: "azure.storage.account",
    provider: "azure",
    display_name: "stprodassets01",
    exposure: "public",
    criticality: "high",
    open_finding_count: 1,
    highest_finding_severity: "high",
  },
  {
    id: "sha256:asset-user-admin",
    tenant_id: TENANT_ID,
    asset_kind: "entra.user",
    provider: "entra_id",
    display_name: "admin@contoso.demo",
    exposure: "internal",
    criticality: "critical",
    open_finding_count: 1,
    highest_finding_severity: "critical",
  },
];
