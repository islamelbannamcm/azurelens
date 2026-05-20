// Section header — title + optional aside (count, timestamp, action link).
//
// Server component; presentational only.

import type { ReactNode } from "react";

interface SectionHeaderProps {
  title: string;
  aside?: ReactNode;
}

export function SectionHeader({ title, aside }: SectionHeaderProps) {
  return (
    <div className="section-header">
      <h2 className="section-title">{title}</h2>
      {aside ? <div className="section-aside">{aside}</div> : null}
    </div>
  );
}
