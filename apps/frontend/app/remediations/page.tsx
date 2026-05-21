// Remediations — roadmap + per-action queue.
//
// Phase 11: reuses the existing `RemediationRoadmap` panel for the status
// strip and shows the full action queue in an enterprise table.

import { getRemediationRoadmap } from "@/lib/api";
import { DEMO_REMEDIATION_ROADMAP } from "@/lib/demo-data";
import { fetchWithFallback } from "@/lib/fetchWithFallback";

import { EmptyState } from "@/components/EmptyState";
import { KpiStrip } from "@/components/KpiStrip";
import { PageHeader } from "@/components/PageHeader";
import { RemediationRoadmap } from "@/components/RemediationRoadmap";
import { SectionHeader } from "@/components/SectionHeader";
import { StatusBadge } from "@/components/StatusBadge";

export const dynamic = "force-dynamic";

export default async function RemediationsPage() {
  const { data, usingFallback, fallbackReason } = await fetchWithFallback({
    fetcher: (signal) => getRemediationRoadmap({ signal }),
    fallback: DEMO_REMEDIATION_ROADMAP,
  });

  return (
    <>
      <PageHeader
        title="Remediations"
        subtitle="Prioritized remediation pipeline. Each action carries a generated runbook (Azure CLI / PowerShell / Bicep) and a rollback path."
        breadcrumbs={[{ label: "Governance", href: "/compliance" }, { label: "Remediations" }]}
        aside={<span>{data.open} open</span>}
      />

      {usingFallback ? (
        <div className="banner" role="status">
          API unreachable
          {fallbackReason ? <> ({fallbackReason})</> : null} — rendering local
          static demo data.
        </div>
      ) : null}

      <KpiStrip
        ariaLabel="Remediation KPIs"
        items={[
          { label: "Open",        value: data.open,        deltaDirection: "up_is_bad" },
          { label: "Suggested",   value: data.suggested },
          { label: "Approved",    value: data.approved },
          { label: "In progress", value: data.in_progress },
          { label: "Succeeded",   value: data.succeeded },
          { label: "Failed",      value: data.failed,      deltaDirection: "up_is_bad" },
        ]}
      />

      <section className="card card-padded" aria-labelledby="section-roadmap">
        <SectionHeader title="Pipeline status" />
        <RemediationRoadmap data={data} />
      </section>

      <section className="card card-padded" aria-labelledby="section-queue">
        <SectionHeader title="Action queue" aside={`${data.next_actions.length} next`} />
        {data.next_actions.length === 0 ? (
          <EmptyState title="No remediations queued" description="The roadmap will populate as new findings land." />
        ) : (
          <table className="table" aria-label="Remediation queue">
            <thead>
              <tr>
                <th>Template</th>
                <th>Finding</th>
                <th style={{ width: 140 }}>Status</th>
                <th style={{ width: 180 }}>Requested</th>
                <th style={{ width: 180 }}>Approved by</th>
              </tr>
            </thead>
            <tbody>
              {data.next_actions.map((a) => (
                <tr key={a.id}>
                  <td><code>{a.template_id}</code></td>
                  <td><code style={{ fontSize: 12 }}>{a.finding_id.slice(0, 8)}…</code></td>
                  <td><StatusBadge kind="remediation-status" value={a.status} /></td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {new Date(a.requested_at).toLocaleString()}
                  </td>
                  <td style={{ color: "var(--color-text-muted)", fontSize: 12 }}>
                    {a.approved_by ? <code>{a.approved_by.slice(0, 8)}…</code> : "—"}
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
