// Findings — enterprise list view.
//
// Phase 11: server-fetches via `listFindings` with graceful fallback to the
// demo dataset, renders the count + severity breakdown as a KpiStrip and a
// full sortable-by-risk table.

import { listFindings } from "@/lib/api";
import { DEMO_FINDINGS } from "@/lib/demo-data";
import { fetchWithFallback } from "@/lib/fetchWithFallback";
import type { FindingSummary, Severity } from "@/types/domain";

import { EmptyState } from "@/components/EmptyState";
import { KpiStrip } from "@/components/KpiStrip";
import { PageHeader } from "@/components/PageHeader";
import { SectionHeader } from "@/components/SectionHeader";
import { StatusBadge } from "@/components/StatusBadge";

export const dynamic = "force-dynamic";

const FALLBACK_PAYLOAD = {
  items: DEMO_FINDINGS,
  page: { next_cursor: null, total_estimate: DEMO_FINDINGS.length },
};

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function countBy<K extends string>(
  items: FindingSummary[],
  key: (f: FindingSummary) => K,
): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const f of items) {
    const k = key(f);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

export default async function FindingsPage() {
  const { data, usingFallback, fallbackReason } = await fetchWithFallback({
    fetcher: (signal) => listFindings({}, { signal }),
    fallback: FALLBACK_PAYLOAD,
  });

  const items = [...data.items].sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 9;
    const sb = SEVERITY_ORDER[b.severity] ?? 9;
    if (sa !== sb) return sa - sb;
    return b.risk_score - a.risk_score;
  });

  const bySeverity = countBy(items, (f) => f.severity);
  const byStatus = countBy(items, (f) => f.status);

  return (
    <>
      <PageHeader
        title="Findings"
        subtitle="Open posture findings across Azure, M365, Defender, Intune, Purview, and Sentinel scanners."
        breadcrumbs={[{ label: "Posture", href: "/" }, { label: "Findings" }]}
        aside={<span>{items.length} total</span>}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data.
        </div>
      ) : null}

      <KpiStrip
        ariaLabel="Findings KPIs"
        items={[
          { label: "Total open",  value: items.filter((f) => f.status === "open").length, deltaDirection: "up_is_bad" },
          { label: "Critical",    value: bySeverity.critical ?? 0, deltaDirection: "up_is_bad" },
          { label: "High",        value: bySeverity.high ?? 0,     deltaDirection: "up_is_bad" },
          { label: "Acknowledged",value: byStatus.acknowledged ?? 0 },
        ]}
      />

      <section className="card card-padded" aria-labelledby="section-findings-list">
        <SectionHeader title="All findings" aside={`${items.length} rows`} />
        {items.length === 0 ? (
          <EmptyState title="No findings" description="No open posture findings in this tenant." />
        ) : (
          <table className="table" aria-label="Findings">
            <thead>
              <tr>
                <th style={{ width: 70 }}>Risk</th>
                <th style={{ width: 110 }}>Severity</th>
                <th style={{ width: 140 }}>Status</th>
                <th>Title</th>
                <th>Asset</th>
                <th style={{ width: 160 }}>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {items.map((f) => (
                <tr key={f.id}>
                  <td className="numeric"><strong>{Math.round(f.risk_score)}</strong></td>
                  <td><StatusBadge kind="severity" value={f.severity} /></td>
                  <td><StatusBadge kind="finding-status" value={f.status} /></td>
                  <td>
                    <div>{f.title}</div>
                    <div className="row-sub"><code>{f.finding_type}</code></div>
                  </td>
                  <td><code style={{ fontSize: 12 }}>{f.asset_id}</code></td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {new Date(f.last_seen_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
