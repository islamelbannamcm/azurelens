// PageHeader — every enterprise page opens with this. Title + optional
// breadcrumbs + optional aside (timestamps, counts, action buttons).
//
// Server component; presentational only.

import Link from "next/link";
import type { ReactNode } from "react";

export interface BreadcrumbItem {
  label: string;
  href?: string;
}

interface PageHeaderProps {
  title: string;
  subtitle?: ReactNode;
  breadcrumbs?: BreadcrumbItem[];
  aside?: ReactNode;
}

export function PageHeader({
  title,
  subtitle,
  breadcrumbs,
  aside,
}: PageHeaderProps) {
  return (
    <div>
      {breadcrumbs && breadcrumbs.length > 0 ? (
        <nav className="breadcrumbs" aria-label="Breadcrumb">
          {breadcrumbs.map((c, i) => {
            const last = i === breadcrumbs.length - 1;
            return (
              <span key={`${i}-${c.label}`}>
                {c.href && !last ? <Link href={c.href}>{c.label}</Link> : <span>{c.label}</span>}
                {!last ? <span className="sep">›</span> : null}
              </span>
            );
          })}
        </nav>
      ) : null}
      <div className="page-header">
        <div>
          <h1 className="page-h-title">{title}</h1>
          {subtitle ? <div className="page-h-sub">{subtitle}</div> : null}
        </div>
        {aside ? <div className="page-h-aside">{aside}</div> : null}
      </div>
    </div>
  );
}
