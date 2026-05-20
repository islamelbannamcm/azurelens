// Remediation roadmap — status counters + the next prioritized actions.
//
// Server component.

import type { RemediationRoadmapSummary } from "@/types/domain";

import { StatusBadge } from "@/components/StatusBadge";

interface RemediationRoadmapProps {
  data: RemediationRoadmapSummary;
}

interface StatTile {
  label: string;
  value: number;
}

export function RemediationRoadmap({ data }: RemediationRoadmapProps) {
  const tiles: StatTile[] = [
    { label: "Open", value: data.open },
    { label: "Suggested", value: data.suggested },
    { label: "Requested", value: data.requested },
    { label: "Approved", value: data.approved },
    { label: "In progress", value: data.in_progress },
    { label: "Succeeded", value: data.succeeded },
    { label: "Failed", value: data.failed },
  ];

  return (
    <div>
      <div className="stat-grid" style={{ marginBottom: 16 }}>
        {tiles.map((t) => (
          <div className="stat" key={t.label}>
            <div className="stat-label">{t.label}</div>
            <div className="stat-value">{t.value}</div>
          </div>
        ))}
      </div>

      {data.next_actions.length > 0 ? (
        <>
          <div className="stat-label" style={{ marginBottom: 6 }}>
            Next actions
          </div>
          <ul className="list">
            {data.next_actions.map((a) => (
              <li className="list-item" key={a.id}>
                <div>
                  <div>
                    <code>{a.template_id}</code>
                  </div>
                  <div className="row-sub">
                    Finding{" "}
                    <code>
                      {a.finding_id.slice(0, 8)}…
                    </code>
                    {a.requested_at ? (
                      <>
                        {" "}·{" "}
                        requested{" "}
                        {new Date(a.requested_at).toLocaleDateString()}
                      </>
                    ) : null}
                  </div>
                </div>
                <StatusBadge kind="remediation-status" value={a.status} />
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p className="empty">No open remediations.</p>
      )}
    </div>
  );
}
