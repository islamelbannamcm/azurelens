// AzureLens — enterprise product shell (Phase 11).
//
// Lays out the Topbar + Sidebar + main content using a single CSS grid
// (see `.shell` in app/globals.css). Server component; no client JS lives
// at this level — interactive bits (active route highlight, search focus)
// are inside `NavLink` and `CommandSearch`.

import type { ReactNode } from "react";

import { Sidebar } from "@/components/shell/Sidebar";
import { Topbar } from "@/components/shell/Topbar";

interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  return (
    <div className="shell">
      <a className="skip-link" href="#shell-main">Skip to main content</a>

      <div className="shell-brand" aria-label="AzureLens">
        <span className="brand-dot" aria-hidden="true" />
        <span className="brand-name">AzureLens</span>
        <span className="brand-env">Demo</span>
      </div>

      <Topbar />
      <Sidebar />

      <main id="shell-main" className="shell-main" tabIndex={-1}>
        {children}
      </main>
    </div>
  );
}
