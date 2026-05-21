// Sidebar — primary product navigation.
//
// Single source of truth for routes (`NAV_GROUPS`) shared with breadcrumbs
// and the future command palette. Server component; the active-route
// highlight is handled inside `NavLink` (client) using `usePathname`.

import { NavLink } from "@/components/shell/NavLink";

interface NavItem {
  href: string;
  label: string;
  ico: string;
}
interface NavGroup {
  title: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    title: "Posture",
    items: [
      { href: "/",             label: "Overview",     ico: "◆" },
      { href: "/findings",     label: "Findings",     ico: "▤" },
      { href: "/threats",      label: "Threats",      ico: "⌖" },
    ],
  },
  {
    title: "Governance",
    items: [
      { href: "/compliance",   label: "Compliance",   ico: "⎙" },
      { href: "/remediations", label: "Remediations", ico: "⎘" },
    ],
  },
  {
    title: "Operations",
    items: [
      { href: "/scans",        label: "Scans",        ico: "↻" },
    ],
  },
];

export function Sidebar() {
  return (
    <nav className="shell-sidebar" aria-label="Primary">
      {NAV_GROUPS.map((group) => (
        <div className="sb-group" key={group.title}>
          <div className="sb-group-title">{group.title}</div>
          {group.items.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              label={item.label}
              ico={item.ico}
            />
          ))}
        </div>
      ))}
      <div className="sb-footer">v0.0.0 · Phase 11 UX</div>
    </nav>
  );
}
