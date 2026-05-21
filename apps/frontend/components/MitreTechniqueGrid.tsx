// MitreTechniqueGrid — renders MITRE ATT&CK technique chips. Chips for
// techniques observed in the tenant (`observed`) are highlighted as active;
// the rest of the catalog renders muted so the gaps and the exposed surface
// area both read at a glance.
//
// The "catalog" used here is intentionally a small Phase-11 fixture; the
// full STIX bundle is ingested by services/threat-intel and will replace
// this in Phase 12 when the techniques API ships.
//
// Server component.

interface MitreTechniqueGridProps {
  observed: string[];
  /** Optional override; defaults to a small representative subset. */
  catalog?: string[];
}

const DEFAULT_CATALOG: string[] = [
  "T1078", "T1078.004", "T1098", "T1133", "T1190",
  "T1110", "T1110.003", "T1566", "T1556.006", "T1562.008",
  "T1530", "T1486", "T1567", "T1021.001", "T1059",
];

export function MitreTechniqueGrid({ observed, catalog = DEFAULT_CATALOG }: MitreTechniqueGridProps) {
  const observedSet = new Set(observed);
  // Show observed first, then catalog techniques not yet observed.
  const ordered = [
    ...observed,
    ...catalog.filter((t) => !observedSet.has(t)),
  ];
  return (
    <div className="chip-row" role="list" aria-label="MITRE ATT&CK techniques">
      {ordered.map((tid) => {
        const isObserved = observedSet.has(tid);
        return (
          <span
            key={tid}
            className={isObserved ? "chip chip-active" : "chip"}
            role="listitem"
            title={isObserved ? `${tid} — observed in tenant` : `${tid} — not currently observed`}
          >
            {tid}
          </span>
        );
      })}
    </div>
  );
}
