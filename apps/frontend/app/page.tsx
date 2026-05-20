// Home dashboard — server component that fetches the composite dashboard
// payload from the API, falling back gracefully to a local static dataset
// when the API is unreachable (e.g. running the frontend in isolation).
//
// Auth + tenant resolution + caching arrive in Phase 1; for now we render
// the deterministic "Contoso Demo" dataset either way.

import { ApiError, getDashboardSummary } from "@/lib/api";
import type { DashboardSummary } from "@/types/domain";

import { ComplianceSummary } from "@/components/ComplianceSummary";
import { RemediationRoadmap } from "@/components/RemediationRoadmap";
import { RiskTable } from "@/components/RiskTable";
import { ScanStatusPanel } from "@/components/ScanStatusPanel";
import { ScoreCard } from "@/components/ScoreCard";
import { SectionHeader } from "@/components/SectionHeader";
import { ThreatExposurePanel } from "@/components/ThreatExposurePanel";

// Demo data is small; render fresh on every request rather than caching.
export const dynamic = "force-dynamic";

const DOMAIN_LABELS: Record<string, string> = {
  identity: "Identity",
  azure_exposure: "Azure exposure",
  device: "Device",
  threat_exposure: "Threat exposure",
  m365_compliance: "M365 compliance",
};

// ---------------------------------------------------------------------------
// Static fallback — mirrors the demo response from
// `apps/api/app/demo/service.py` exactly. Used only when the API is
// unreachable so the dashboard still renders for design / preview / CI.
// ---------------------------------------------------------------------------

const FALLBACK_DASHBOARD: DashboardSummary = {
  tenant_id: "00000000-0000-0000-0000-000000000001",
  tenant_name: "Contoso Demo",
  overall: {
    score_kind: "overall",
    value: 64,
    band: "moderate",
    calculated_at: "2026-05-20T10:00:00Z",
    delta_7d: 5,
  },
  domain_scores: [
    { score_kind: "identity", value: 58, band: "weak" },
    { score_kind: "azure_exposure", value: 52, band: "weak" },
    { score_kind: "device", value: 71, band: "moderate" },
    { score_kind: "threat_exposure", value: 60, band: "moderate" },
    { score_kind: "m365_compliance", value: 79, band: "strong" },
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
        tenant_id: "00000000-0000-0000-0000-000000000001",
        campaign_id: "campaign::akira-rdp-2026q2",
        campaign_name: "Akira ransomware — RDP brute-force wave",
        affected_asset_count: 1,
        highest_severity: "critical",
        correlation_dimensions: ["technique_to_finding"],
        last_observed_at: "2026-05-20T10:00:00Z",
      },
      {
        tenant_id: "00000000-0000-0000-0000-000000000001",
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
      "T1078",
      "T1078.004",
      "T1098",
      "T1110.003",
      "T1133",
      "T1190",
      "T1486",
      "T1530",
      "T1556.006",
      "T1562.008",
      "T1567",
    ],
    correlation_count: 2,
  },
  compliance_summary: [
    {
      framework: "cis_azure",
      version: "2.1.0",
      score: 68,
      non_compliant: 20,
      partially_compliant: 22,
    },
    {
      framework: "mcsb",
      version: "1.0",
      score: 71,
      non_compliant: 12,
      partially_compliant: 18,
    },
    {
      framework: "nist_csf",
      version: "2.0",
      score: 72,
      non_compliant: 12,
      partially_compliant: 22,
    },
    {
      framework: "iso_27001",
      version: "2022",
      score: 74,
      non_compliant: 8,
      partially_compliant: 20,
    },
    {
      framework: "soc2",
      version: "2017",
      score: 79,
      non_compliant: 2,
      partially_compliant: 6,
    },
    {
      framework: "gdpr",
      version: "2018",
      score: 81,
      non_compliant: 1,
      partially_compliant: 4,
    },
  ],
  recent_scan: {
    scan_id: "11111111-2222-3333-4444-555555555555",
    kinds: ["full"],
    status: "completed",
    requested_at: "2026-05-20T09:00:00Z",
    completed_at: "2026-05-20T10:00:00Z",
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
        tenant_id: "00000000-0000-0000-0000-000000000001",
        id: "dddd0001-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa1-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.identity.enforce_mfa_privileged.v2",
        status: "suggested",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: null,
        requested_at: "2026-05-18T12:00:00Z",
        started_at: null,
        ended_at: null,
        diff_before: {},
        diff_after: {},
        error_summary: null,
      },
      {
        tenant_id: "00000000-0000-0000-0000-000000000001",
        id: "dddd0002-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa4-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.azure.nsg.restrict_rdp.v1",
        status: "requested",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: null,
        requested_at: "2026-05-19T12:00:00Z",
        started_at: null,
        ended_at: null,
        diff_before: {},
        diff_after: {},
        error_summary: null,
      },
      {
        tenant_id: "00000000-0000-0000-0000-000000000001",
        id: "dddd0003-dddd-dddd-dddd-dddddddddddd",
        finding_id: "aaaaaaa5-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        template_id: "rt.azure.storage.disable_public.v1",
        status: "approved",
        requested_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        approved_by: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
        requested_at: "2026-05-19T16:00:00Z",
        started_at: null,
        ended_at: null,
        diff_before: {},
        diff_after: {},
        error_summary: null,
      },
    ],
  },
  generated_at: "2026-05-20T12:00:00Z",
};

// ---------------------------------------------------------------------------
// Data acquisition with timeout + graceful fallback
// ---------------------------------------------------------------------------

interface FetchOutcome {
  data: DashboardSummary;
  usingFallback: boolean;
  fallbackReason?: string;
}

async function fetchDashboard(): Promise<FetchOutcome> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2_500);
  try {
    const data = await getDashboardSummary({ signal: controller.signal });
    return { data, usingFallback: false };
  } catch (err) {
    let reason = "unknown error";
    if (err instanceof ApiError) {
      reason = `HTTP ${err.status} (${err.code})`;
    } else if (err instanceof DOMException && err.name === "AbortError") {
      reason = "timed out after 2.5s";
    } else if (err instanceof TypeError) {
      // Native fetch reports network failure (ECONNREFUSED, DNS, etc.) as TypeError.
      reason = "network unreachable";
    } else if (err instanceof Error) {
      reason = err.message;
    }
    return { data: FALLBACK_DASHBOARD, usingFallback: true, fallbackReason: reason };
  } finally {
    clearTimeout(timer);
  }
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default async function HomePage() {
  const { data, usingFallback, fallbackReason } = await fetchDashboard();
  const overall = data.overall;
  const generated = new Date(data.generated_at).toLocaleString();

  return (
    <>
      <SectionHeader
        title={`Posture overview — ${data.tenant_name}`}
        aside={`Generated ${generated}`}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data. Start the backend with{" "}
          <code>uvicorn app.main:app --reload --port 8000</code> to load
          live demo data.
        </div>
      ) : null}

      <section className="score-grid" aria-label="Posture scores">
        <ScoreCard
          kind="overall"
          label="Overall posture"
          value={overall.value}
          band={overall.band}
          size="large"
          delta={overall.delta_7d}
        />
        <div className="score-domain-grid">
          {data.domain_scores.map((d) => (
            <ScoreCard
              key={d.score_kind}
              kind={d.score_kind}
              label={DOMAIN_LABELS[d.score_kind] ?? d.score_kind}
              value={d.value}
              band={d.band}
              size="small"
            />
          ))}
        </div>
      </section>

      <section className="card card-padded" aria-labelledby="section-top-risks">
        <SectionHeader
          title="Top risks"
          aside={`${data.top_risks.length} shown`}
        />
        <RiskTable items={data.top_risks} />
      </section>

      <div className="two-col">
        <section className="card card-padded" aria-labelledby="section-threats">
          <SectionHeader title="Threat exposure" />
          <ThreatExposurePanel data={data.threat_exposure} />
        </section>
        <section className="card card-padded" aria-labelledby="section-compliance">
          <SectionHeader title="Compliance frameworks" />
          <ComplianceSummary items={data.compliance_summary} />
        </section>
      </div>

      <section className="card card-padded" aria-labelledby="section-remediation">
        <SectionHeader
          title="Remediation roadmap"
          aside={`${data.remediation_roadmap.open} open`}
        />
        <RemediationRoadmap data={data.remediation_roadmap} />
      </section>

      <section className="card card-padded" aria-labelledby="section-scan">
        <SectionHeader title="Recent scan" />
        <ScanStatusPanel data={data.recent_scan} />
      </section>
    </>
  );
}
