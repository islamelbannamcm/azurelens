// Risk table — top open findings ranked by risk score.
//
// Server component.

import type { TopRiskItem } from "@/types/domain";

import { StatusBadge } from "@/components/StatusBadge";

interface RiskTableProps {
  items: TopRiskItem[];
}

export function RiskTable({ items }: RiskTableProps) {
  if (items.length === 0) {
    return <p className="empty">No open risks.</p>;
  }
  return (
    <table className="table" aria-label="Top open risks ranked by risk score">
      <thead>
        <tr>
          <th style={{ width: 70 }} scope="col">Risk</th>
          <th style={{ width: 110 }} scope="col">Severity</th>
          <th scope="col">Title</th>
          <th scope="col">Asset</th>
        </tr>
      </thead>
      <tbody>
        {items.map((item) => (
          <tr key={item.finding_id}>
            <td className="numeric">
              <strong>{Math.round(item.risk_score)}</strong>
            </td>
            <td>
              <StatusBadge kind="severity" value={item.severity} />
            </td>
            <td>
              <div>{item.title}</div>
              <div className="row-sub">
                <code>{item.finding_type}</code>
              </div>
            </td>
            <td>
              <code style={{ fontSize: 12 }}>{item.asset_id}</code>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
