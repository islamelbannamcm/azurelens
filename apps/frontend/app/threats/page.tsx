// Threats — live threat exposure view.
//
// Combines the dashboard's threat exposure summary with the campaign
// exposure list and a MITRE technique grid. Both API calls fall back to the
// shared demo dataset independently so a partial outage still renders.

import { getThreatExposureSummary, listCampaignExposure } from "@/lib/api";
import { DEMO_CAMPAIGNS, DEMO_THREAT_EXPOSURE } from "@/lib/demo-data";
import { fetchWithFallback } from "@/lib/fetchWithFallback";

import { EmptyState } from "@/components/EmptyState";
import { KpiStrip } from "@/components/KpiStrip";
import { MitreTechniqueGrid } from "@/components/MitreTechniqueGrid";
import { PageHeader } from "@/components/PageHeader";
import { SectionHeader } from "@/components/SectionHeader";
import { StatusBadge } from "@/components/StatusBadge";

export const dynamic = "force-dynamic";

export default async function ThreatsPage() {
  const [exposure, campaigns] = await Promise.all([
    fetchWithFallback({
      fetcher: (signal) => getThreatExposureSummary({ signal }),
      fallback: DEMO_THREAT_EXPOSURE,
    }),
    fetchWithFallback({
      fetcher: (signal) => listCampaignExposure({ signal }),
      fallback: DEMO_CAMPAIGNS,
    }),
  ]);

  const usingFallback = exposure.usingFallback || campaigns.usingFallback;
  const fallbackReason = exposure.fallbackReason ?? campaigns.fallbackReason;

  return (
    <>
      <PageHeader
        title="Threats"
        subtitle="Live threat-intel correlation: active campaigns, KEV CVEs, and MITRE ATT&CK techniques observed in tenant."
        breadcrumbs={[{ label: "Posture", href: "/" }, { label: "Threats" }]}
        aside={<span>{campaigns.data.length} active campaigns</span>}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data.
        </div>
      ) : null}

      <KpiStrip
        ariaLabel="Threat KPIs"
        items={[
          { label: "Active campaigns",   value: campaigns.data.length,                          deltaDirection: "up_is_bad" },
          { label: "KEV CVEs affecting", value: exposure.data.kev_cve_count,                    deltaDirection: "up_is_bad" },
          { label: "Correlations",       value: exposure.data.correlation_count,                deltaDirection: "up_is_bad" },
          { label: "Techniques observed",value: exposure.data.mitre_techniques_observed.length, deltaDirection: "up_is_bad" },
        ]}
      />

      <section className="card card-padded" aria-labelledby="section-campaigns">
        <SectionHeader
          title="Active campaign exposure"
          aside={`${campaigns.data.length} correlated to this tenant`}
        />
        {campaigns.data.length === 0 ? (
          <EmptyState title="No active campaign correlations" />
        ) : (
          <table className="table" aria-label="Active campaigns">
            <thead>
              <tr>
                <th>Campaign</th>
                <th style={{ width: 140 }}>Highest severity</th>
                <th style={{ width: 120 }}>Affected</th>
                <th>Correlation</th>
                <th style={{ width: 180 }}>Last observed</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.data.map((c) => (
                <tr key={c.campaign_id}>
                  <td>
                    <div>{c.campaign_name}</div>
                    <div className="row-sub"><code>{c.campaign_id}</code></div>
                  </td>
                  <td><StatusBadge kind="severity" value={c.highest_severity} /></td>
                  <td className="numeric">{c.affected_asset_count}</td>
                  <td>
                    <div className="chip-row">
                      {c.correlation_dimensions.map((d) => (
                        <span className="chip" key={d}>{d}</span>
                      ))}
                    </div>
                  </td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {new Date(c.last_observed_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="card card-padded" aria-labelledby="section-mitre">
        <SectionHeader
          title="MITRE ATT&CK — techniques observed in tenant"
          aside={`${exposure.data.mitre_techniques_observed.length} of catalog`}
        />
        <MitreTechniqueGrid observed={exposure.data.mitre_techniques_observed} />
        <p style={{ color: "var(--color-text-muted)", fontSize: 12, marginTop: 12 }}>
          Highlighted chips are observed in tenant findings. Phase 12 ships
          the full ATT&CK matrix view with per-tactic exposure scoring and
          detection-coverage overlay.
        </p>
      </section>
    </>
  );
}
