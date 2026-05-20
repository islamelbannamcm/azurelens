// Status badge — semantic colored pill for severity / band / status values.
//
// One component, multiple value taxonomies (severity, score-band, finding /
// scan / remediation status). All class mappings are deterministic so this
// can stay a server component.

type BadgeKind =
  | "severity"
  | "band"
  | "finding-status"
  | "scan-status"
  | "remediation-status"
  | "neutral";

interface StatusBadgeProps {
  kind?: BadgeKind;
  value: string;
  label?: string;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: "badge badge-critical",
  high: "badge badge-high",
  medium: "badge badge-medium",
  low: "badge badge-low",
  info: "badge badge-info",
};

const BAND_CLASS: Record<string, string> = {
  critical: "badge badge-critical",
  weak: "badge badge-band-weak",
  moderate: "badge badge-band-moderate",
  strong: "badge badge-band-strong",
  excellent: "badge badge-band-excellent",
};

const STATUS_CLASS: Record<string, string> = {
  // scan
  completed: "badge badge-success",
  succeeded: "badge badge-success",
  queued: "badge badge-info",
  running: "badge badge-low",
  partial: "badge badge-medium",
  failed: "badge badge-critical",
  cancelled: "badge badge-info",
  // remediation
  not_started: "badge badge-info",
  suggested: "badge badge-low",
  requested: "badge badge-medium",
  approved: "badge badge-low",
  executing: "badge badge-low",
  rolled_back: "badge badge-info",
  // finding
  open: "badge badge-critical",
  acknowledged: "badge badge-medium",
  suppressed: "badge badge-info",
  remediated: "badge badge-success",
  false_positive: "badge badge-info",
};

function classFor(kind: BadgeKind, value: string): string {
  const v = value.toLowerCase();
  switch (kind) {
    case "severity":
      return SEVERITY_CLASS[v] ?? "badge";
    case "band":
      return BAND_CLASS[v] ?? "badge";
    case "finding-status":
    case "scan-status":
    case "remediation-status":
      return STATUS_CLASS[v] ?? "badge";
    case "neutral":
    default:
      return "badge";
  }
}

export function StatusBadge({ kind = "neutral", value, label }: StatusBadgeProps) {
  const display = label ?? value.replace(/_/g, " ");
  return <span className={classFor(kind, value)}>{display}</span>;
}
