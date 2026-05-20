// Score card — large variant for the overall posture, small variant for
// per-domain breakdowns. Higher value = better posture (display direction).
//
// Server component.

import type { ScoreBand, ScoreKind } from "@/types/domain";

import { StatusBadge } from "@/components/StatusBadge";

interface ScoreCardProps {
  kind: ScoreKind | string;
  label: string;
  value: number;
  band: ScoreBand | string;
  size?: "large" | "small";
  /** Signed delta vs. ~7 days ago. Positive = improvement. */
  delta?: number;
}

function formatDelta(
  delta: number | undefined,
): { className: string; text: string } | null {
  if (delta === undefined) return null;
  if (delta > 0) return { className: "score-delta-pos", text: `+${delta} (7d)` };
  if (delta < 0) return { className: "score-delta-neg", text: `${delta} (7d)` };
  return { className: "score-delta-zero", text: "no change (7d)" };
}

export function ScoreCard({
  kind,
  label,
  value,
  band,
  size = "small",
  delta,
}: ScoreCardProps) {
  const isLarge = size === "large";
  const cardClass = `score-card${isLarge ? " score-card-large" : ""}`;
  const valueClass = `score-value${isLarge ? " score-value-large" : ""}`;
  const deltaParts = formatDelta(delta);

  return (
    <div
      className={cardClass}
      data-score-kind={kind}
      aria-label={`${label} score ${value} ${band}`}
    >
      <div className="score-kind">{label}</div>
      <div className={valueClass}>{value}</div>
      <div className="score-meta">
        <StatusBadge kind="band" value={String(band)} />
        {deltaParts ? (
          <span className={deltaParts.className}>{deltaParts.text}</span>
        ) : null}
      </div>
    </div>
  );
}
