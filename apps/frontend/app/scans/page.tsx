// Scans — scanner run history.
//
// Phase 11: KPIs (last run, success rate, findings produced) + a table of
// recent runs with kind, trigger, partition progress, and error summary.

import { listScans } from "@/lib/api";
import { DEMO_SCANS } from "@/lib/demo-data";
import { fetchWithFallback } from "@/lib/fetchWithFallback";

import { EmptyState } from "@/components/EmptyState";
import { KpiStrip } from "@/components/KpiStrip";
import { PageHeader } from "@/components/PageHeader";
import { SectionHeader } from "@/components/SectionHeader";
import { StatusBadge } from "@/components/StatusBadge";

export const dynamic = "force-dynamic";

function formatRelative(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diffMin = Math.round((Date.now() - then) / 60_000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  return `${Math.round(diffHr / 24)}d ago`;
}

export default async function ScansPage() {
  const { data, usingFallback, fallbackReason } = await fetchWithFallback({
    fetcher: (signal) => listScans({ signal }),
    fallback: DEMO_SCANS,
  });

  const ordered = [...data].sort((a, b) => {
    const ta = new Date(a.requested_at).getTime();
    const tb = new Date(b.requested_at).getTime();
    return tb - ta;
  });

  const total = ordered.length;
  const succeeded = ordered.filter((s) => s.status === "completed").length;
  const failed = ordered.filter((s) => s.status === "failed" || s.status === "partial").length;
  const findings = ordered.reduce((acc, s) => acc + s.findings_produced, 0);
  const mostRecent = ordered[0];

  return (
    <>
      <PageHeader
        title="Scans"
        subtitle="Per-source scan history across Azure Resource Graph, Microsoft Graph, Defender, Intune, Sentinel, and Purview scanners."
        breadcrumbs={[{ label: "Operations", href: "/scans" }, { label: "Scans" }]}
        aside={<span>{total} runs</span>}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data.
        </div>
      ) : null}

      <KpiStrip
        ariaLabel="Scan KPIs"
        items={[
          {
            label: "Last run",
            value: mostRecent ? formatRelative(mostRecent.completed_at ?? mostRecent.requested_at) : "—",
            sub: mostRecent ? <span>{mostRecent.kinds.join(", ")}</span> : null,
          },
          { label: "Succeeded",         value: succeeded },
          { label: "Failed / partial",  value: failed, deltaDirection: "up_is_bad" },
          { label: "Findings produced", value: findings },
        ]}
      />

      <section className="card card-padded" aria-labelledby="section-runs">
        <SectionHeader title="Recent runs" aside={`${ordered.length} rows`} />
        {ordered.length === 0 ? (
          <EmptyState title="No scans yet" description="Trigger a scan from the API to populate this view." />
        ) : (
          <table className="table" aria-label="Recent scan runs">
            <thead>
              <tr>
                <th style={{ width: 140 }}>Status</th>
                <th>Kinds</th>
                <th style={{ width: 130 }}>Trigger</th>
                <th style={{ width: 120 }}>Partitions</th>
                <th style={{ width: 110 }}>Findings</th>
                <th style={{ width: 180 }}>Requested</th>
                <th>Error</th>
              </tr>
            </thead>
            <tbody>
              {ordered.map((s) => (
                <tr key={s.id}>
                  <td><StatusBadge kind="scan-status" value={s.status} /></td>
                  <td>
                    <div className="chip-row">
                      {s.kinds.map((k) => <span className="chip" key={k}>{k}</span>)}
                    </div>
                  </td>
                  <td>{s.trigger_type.replace(/_/g, " ")}</td>
                  <td className="numeric">
                    {s.partitions_completed}
                    {s.partitions_total !== null ? ` / ${s.partitions_total}` : ""}
                  </td>
                  <td className="numeric">{s.findings_produced}</td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {new Date(s.requested_at).toLocaleString()}
                  </td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {s.error_summary ?? "—"}
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
