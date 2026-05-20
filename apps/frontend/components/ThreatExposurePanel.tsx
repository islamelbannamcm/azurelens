// Threat exposure panel — active campaigns, KEV count, technique chips.
//
// Server component.

import type { ThreatExposureSummary } from "@/types/domain";

import { StatusBadge } from "@/components/StatusBadge";

interface ThreatExposurePanelProps {
  data: ThreatExposureSummary;
}

export function ThreatExposurePanel({ data }: ThreatExposurePanelProps) {
  return (
    <div>
      <div className="stat-grid" style={{ marginBottom: 16 }}>
        <div className="stat">
          <div className="stat-label">Active campaigns</div>
          <div className="stat-value">{data.active_campaigns.length}</div>
        </div>
        <div className="stat">
          <div className="stat-label">KEV CVEs</div>
          <div className="stat-value">{data.kev_cve_count}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Correlations</div>
          <div className="stat-value">{data.correlation_count}</div>
        </div>
        <div className="stat">
          <div className="stat-label">Techniques</div>
          <div className="stat-value">{data.mitre_techniques_observed.length}</div>
        </div>
      </div>

      {data.active_campaigns.length > 0 ? (
        <ul className="list" style={{ marginBottom: 16 }}>
          {data.active_campaigns.map((c) => (
            <li className="list-item" key={c.campaign_id}>
              <div>
                <div>{c.campaign_name}</div>
                <div className="row-sub">
                  {c.affected_asset_count} affected asset
                  {c.affected_asset_count === 1 ? "" : "s"}
                  {c.correlation_dimensions.length > 0 ? (
                    <>
                      {" "}·{" "}
                      <code>{c.correlation_dimensions.join(", ")}</code>
                    </>
                  ) : null}
                </div>
              </div>
              <StatusBadge kind="severity" value={c.highest_severity} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="empty">No active campaign correlations.</p>
      )}

      {data.mitre_techniques_observed.length > 0 ? (
        <div>
          <div className="stat-label" style={{ marginBottom: 6 }}>
            MITRE techniques observed
          </div>
          <div className="chip-row">
            {data.mitre_techniques_observed.map((t) => (
              <span className="chip" key={t}>
                {t}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}
