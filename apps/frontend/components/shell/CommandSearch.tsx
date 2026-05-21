"use client";

// CommandSearch — topbar search input with a `/` keyboard shortcut.
//
// The `/` key focuses this input from anywhere on the page, except when
// the user is already typing in another input/textarea/contenteditable.
// Real command-palette behavior (⌘K, route jump, finding jump) lands in
// Phase 12 alongside TanStack Query.

import { useEffect, useRef } from "react";

interface CommandSearchProps {
  placeholder?: string;
  ariaLabel?: string;
}

export function CommandSearch({
  placeholder = "Search…",
  ariaLabel = "Search",
}: CommandSearchProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "/" || e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement | null;
      const tag = target?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || target?.isContentEditable) return;
      e.preventDefault();
      inputRef.current?.focus();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  return (
    <input
      ref={inputRef}
      type="search"
      className="topbar-search"
      placeholder={placeholder}
      aria-label={ariaLabel}
    />
  );
}
