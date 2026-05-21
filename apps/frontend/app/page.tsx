// Overview — executive posture dashboard.
//
// Phase 11 refactor: extracted the FALLBACK constant into `lib/demo-data.ts`,
// adopted the shared `fetchWithFallback` helper, opens with `PageHeader` +
// `KpiStrip`, and renders inside the Phase-11 enterprise `AppShell`.

import { getDashboardSummary } from "@/lib/api";
import { DEMO_DASHBOARD } from "@/lib/demo-data";
import { fetchWithFallback } from "@/lib/fetchWithFallback";

import { ComplianceSummary } from "@/components/ComplianceSummary";
import { KpiStrip } from "@/components/KpiStrip";
import { PageHeader } from "@/components/PageHeader";
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

export default async function OverviewPage() {
  const { data, usingFallback, fallbackReason } = await fetchWithFallback({
    fetcher: (signal) => getDashboardSummary({ signal }),
    fallback: DEMO_DASHBOARD,
  });

  const overall = data.overall;
  const generated = new Date(data.generated_at).toLocaleString();

  return (
    <>
      <PageHeader
        title="Overview"
        subtitle={`Executive posture — ${data.tenant_name}`}
        breadcrumbs={[{ label: "Posture", href: "/" }, { label: "Overview" }]}
        aside={<span>Generated {generated}</span>}
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

      <KpiStrip
        ariaLabel="Posture KPIs"
        items={[
          {
            label: "Overall posture",
            value: overall.value,
            unit: "/100",
            delta: overall.delta_7d,
            sub: <span>vs. 7 days ago · band: {overall.band}</span>,
          },
          {
            label: "Open critical risks",
            value: data.top_risks.filter((r) => r.severity === "critical").length,
            sub: <span>severity = critical</span>,
            deltaDirection: "up_is_bad",
          },
          {
            label: "Active campaigns",
            value: data.threat_exposure.active_campaigns.length,
            sub: <span>{data.threat_exposure.correlation_count} correlations</span>,
            deltaDirection: "up_is_bad",
          },
          {
            label: "Open remediations",
            value: data.remediation_roadmap.open,
            sub: (
              <span>
                {data.remediation_roadmap.in_progress} in progress ·{" "}
                {data.remediation_roadmap.succeeded} succeeded
              </span>
            ),
          },
        ]}
      />

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
        <SectionHeader title="Top risks" aside={`${data.top_risks.length} shown`} />
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
