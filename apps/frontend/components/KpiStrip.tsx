// KpiStrip — Defender-style stat tiles: label, value, optional unit, delta,
// and a tiny subtitle. Used by Overview, Threats, Compliance, Remediations.
//
// Server component.

import type { ReactNode } from "react";

export interface KpiItem {
  label: string;
  value: number | string;
  unit?: string;
  /** Positive = improvement (green ↑). Negative = regression (red ↓). */
  delta?: number;
  /** "up means better" (default) or "up means worse". */
  deltaDirection?: "up_is_good" | "up_is_bad";
  sub?: ReactNode;
}

interface KpiStripProps {
  items: KpiItem[];
  ariaLabel?: string;
}

export function KpiStrip({ items, ariaLabel }: KpiStripProps) {
  return (
    <div className="kpi-strip" role="list" aria-label={ariaLabel}>
      {items.map((it) => {
        const deltaClass = deltaClassFor(it.delta, it.deltaDirection);
        return (
          <div className="kpi" role="listitem" key={it.label}>
            <div className="kpi-label">{it.label}</div>
            <div className="kpi-row">
              <div className="kpi-value">{it.value}</div>
              {it.unit ? <div className="kpi-unit">{it.unit}</div> : null}
              {it.delta !== undefined ? (
                <span className={`kpi-delta ${deltaClass}`}>
                  {it.delta > 0 ? "▲" : it.delta < 0 ? "▼" : "·"}{" "}
                  {Math.abs(it.delta)}
                </span>
              ) : null}
            </div>
            {it.sub ? <div className="kpi-sub">{it.sub}</div> : null}
          </div>
        );
      })}
    </div>
  );
}

function deltaClassFor(
  delta: number | undefined,
  direction: KpiItem["deltaDirection"] = "up_is_good",
): "up" | "down" | "" {
  if (delta === undefined || delta === 0) return "";
  const good = direction === "up_is_good" ? delta > 0 : delta < 0;
  return good ? "up" : "down";
}
