// EmptyState — uniform "nothing to show" placeholder used across the new
// routes. Pairs with `.empty-state` styles in app/globals.css.
//
// Server component.

import type { ReactNode } from "react";

interface EmptyStateProps {
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="empty-state" role="status">
      <div className="es-title">{title}</div>
      {description ? <div className="es-sub">{description}</div> : null}
      {action ? <div style={{ marginTop: 12 }}>{action}</div> : null}
    </div>
  );
}
