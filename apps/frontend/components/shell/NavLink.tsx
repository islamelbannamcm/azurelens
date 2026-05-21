"use client";

// Sidebar nav link — highlights itself when the current pathname matches.
//
// Client component so it can read `usePathname()`. Kept tiny so the rest of
// the shell remains server-rendered.

import Link from "next/link";
import { usePathname } from "next/navigation";

interface NavLinkProps {
  href: string;
  label: string;
  ico: string;
}

export function NavLink({ href, label, ico }: NavLinkProps) {
  const pathname = usePathname() ?? "/";
  const isActive =
    href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(href + "/");

  return (
    <Link
      href={href}
      className={isActive ? "sb-link active" : "sb-link"}
      aria-current={isActive ? "page" : undefined}
    >
      <span className="sb-ico" aria-hidden="true">{ico}</span>
      <span className="sb-label">{label}</span>
    </Link>
  );
}
