// Compliance summary — per-framework progress bars.
//
// Score-band thresholds mirror the backend `WeightProfile.band_thresholds`
// defaults in services/risk-engine/risk_engine/weights.py.
//
// Server component.

import type { ComplianceFrameworkSummary } from "@/types/domain";

interface ComplianceSummaryProps {
  items: ComplianceFrameworkSummary[];
}

const FRAMEWORK_LABEL: Record<string, string> = {
  cis_azure: "CIS Azure",
  mcsb: "MCSB",
  nist_csf: "NIST CSF",
  nist_800_53: "NIST 800-53",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
  gdpr: "GDPR",
  zero_trust: "Zero Trust",
  azure_waf: "Azure WAF",
  m365_baseline: "M365 baseline",
  cis_m365: "CIS M365",
  hipaa: "HIPAA",
  pci_dss: "PCI DSS",
};

function bandForScore(score: number): string {
  if (score >= 90) return "excellent";
  if (score >= 75) return "strong";
  if (score >= 60) return "moderate";
  if (score >= 40) return "weak";
  return "critical";
}

export function ComplianceSummary({ items }: ComplianceSummaryProps) {
  if (items.length === 0) {
    return <p className="empty">No frameworks evaluated yet.</p>;
  }
  return (
    <div role="list" aria-label="Compliance frameworks">
      {items.map((item) => {
        const score = Math.round(item.score);
        const band = bandForScore(score);
        const label = FRAMEWORK_LABEL[item.framework] ?? item.framework;
        return (
          <div
            className="bar-row"
            key={item.framework}
            role="listitem"
            aria-label={`${label} ${score} ${band}`}
          >
            <div>
              <div>{label}</div>
              <div className="row-sub">
                v{item.version}
                {item.non_compliant > 0
                  ? ` · ${item.non_compliant} non-compliant`
                  : ""}
              </div>
            </div>
            <div
              className="bar-track"
              role="progressbar"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={score}
            >
              <div
                className={`bar-fill bar-fill-${band}`}
                style={{ width: `${score}%` }}
              />
            </div>
            <div className="numeric" style={{ textAlign: "right" }}>
              {score}
            </div>
          </div>
        );
      })}
    </div>
  );
}
