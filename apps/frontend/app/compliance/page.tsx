// Compliance — per-framework coverage center.
//
// Phase 11: KPI strip with aggregate counts + the existing ComplianceSummary
// component as the per-framework score view + a table of failing/partial
// control counts for auditor handoff.

import { getComplianceSummary } from "@/lib/api";
import { ComplianceSummary } from "@/components/ComplianceSummary";
import { DEMO_COMPLIANCE } from "@/lib/demo-data";
import { EmptyState } from "@/components/EmptyState";
import { KpiStrip } from "@/components/KpiStrip";
import { PageHeader } from "@/components/PageHeader";
import { SectionHeader } from "@/components/SectionHeader";
import { fetchWithFallback } from "@/lib/fetchWithFallback";

export const dynamic = "force-dynamic";

const FRAMEWORK_LABEL: Record<string, string> = {
  cis_azure: "CIS Azure",
  mcsb: "MCSB",
  nist_csf: "NIST CSF",
  nist_800_53: "NIST 800-53",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
  gdpr: "GDPR",
  zero_trust: "Zero Trust",
  azure_waf: "Azure WAF",
  m365_baseline: "M365 baseline",
  cis_m365: "CIS M365",
  hipaa: "HIPAA",
  pci_dss: "PCI DSS",
};

export default async function CompliancePage() {
  const { data, usingFallback, fallbackReason } = await fetchWithFallback({
    fetcher: (signal) => getComplianceSummary({ signal }),
    fallback: DEMO_COMPLIANCE,
  });

  const totalNonCompliant = data.reduce((acc, f) => acc + f.non_compliant, 0);
  const totalPartial = data.reduce((acc, f) => acc + f.partially_compliant, 0);
  const avgScore = data.length
    ? Math.round(data.reduce((acc, f) => acc + f.score, 0) / data.length)
    : 0;

  return (
    <>
      <PageHeader
        title="Compliance"
        subtitle="Per-framework coverage mapped from canonical findings. Evidence is pinned to immutable blob storage for auditor handoff."
        breadcrumbs={[{ label: "Governance", href: "/compliance" }, { label: "Compliance" }]}
        aside={<span>{data.length} frameworks</span>}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data.
        </div>
      ) : null}

      <KpiStrip
        ariaLabel="Compliance KPIs"
        items={[
          { label: "Frameworks tracked",   value: data.length },
          { label: "Mean score",           value: avgScore, unit: "/100" },
          { label: "Non-compliant ctrls",  value: totalNonCompliant, deltaDirection: "up_is_bad" },
          { label: "Partial ctrls",        value: totalPartial,      deltaDirection: "up_is_bad" },
        ]}
      />

      <section className="card card-padded" aria-labelledby="section-coverage">
        <SectionHeader title="Coverage by framework" />
        <ComplianceSummary items={data} />
      </section>

      <section className="card card-padded" aria-labelledby="section-control-counts">
        <SectionHeader title="Controls by framework" aside="non-compliant + partial = audit backlog" />
        {data.length === 0 ? (
          <EmptyState title="No frameworks evaluated yet." />
        ) : (
          <table className="table" aria-label="Controls by framework">
            <thead>
              <tr>
                <th>Framework</th>
                <th style={{ width: 100 }}>Version</th>
                <th style={{ width: 100 }}>Score</th>
                <th style={{ width: 140 }}>Non-compliant</th>
                <th style={{ width: 140 }}>Partial</th>
                <th style={{ width: 140 }}>Backlog</th>
              </tr>
            </thead>
            <tbody>
              {data.map((f) => (
                <tr key={f.framework}>
                  <td>{FRAMEWORK_LABEL[f.framework] ?? f.framework}</td>
                  <td className="numeric">v{f.version}</td>
                  <td className="numeric"><strong>{Math.round(f.score)}</strong></td>
                  <td className="numeric">{f.non_compliant}</td>
                  <td className="numeric">{f.partially_compliant}</td>
                  <td className="numeric"><strong>{f.non_compliant + f.partially_compliant}</strong></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
