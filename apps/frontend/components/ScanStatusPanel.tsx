// Scan status panel — most-recent-scan summary.
//
// Server component.

import type { RecentScanSummary } from "@/types/domain";

import { StatusBadge } from "@/components/StatusBadge";

interface ScanStatusPanelProps {
  data: RecentScanSummary;
}

function formatRelative(iso: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diffMin = Math.round((Date.now() - then) / 60_000);
  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.round(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDay = Math.round(diffHr / 24);
  return `${diffDay}d ago`;
}

export function ScanStatusPanel({ data }: ScanStatusPanelProps) {
  if (!data.scan_id) {
    return <p className="empty">No scans yet.</p>;
  }
  return (
    <div className="stat-grid">
      <div className="stat">
        <div className="stat-label">Status</div>
        <div style={{ marginTop: 2 }}>
          {data.status ? (
            <StatusBadge kind="scan-status" value={data.status} />
          ) : (
            "—"
          )}
        </div>
      </div>
      <div className="stat">
        <div className="stat-label">Kinds</div>
        <div className="stat-value" style={{ fontSize: 14 }}>
          {data.kinds.join(", ") || "—"}
        </div>
      </div>
      <div className="stat">
        <div className="stat-label">Findings</div>
        <div className="stat-value">{data.findings_produced}</div>
      </div>
      <div className="stat">
        <div className="stat-label">Completed</div>
        <div className="stat-value" style={{ fontSize: 14 }}>
          {formatRelative(data.completed_at)}
        </div>
      </div>
    </div>
  );
}
