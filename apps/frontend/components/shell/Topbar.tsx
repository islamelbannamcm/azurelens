// Topbar — tenant switcher, command search, actions, avatar.
//
// Server component shell. The search input is wrapped by `CommandSearch`
// (client) so the `/` shortcut focuses it without making this whole bar
// a client boundary.

import { CommandSearch } from "@/components/shell/CommandSearch";

export function Topbar() {
  return (
    <header className="shell-topbar" role="banner">
      <button className="tenant-switch" type="button" aria-label="Switch tenant">
        <span>Contoso Demo</span>
        <span aria-hidden="true">▾</span>
      </button>

      <CommandSearch
        placeholder="Search findings, assets, techniques, KQL…   ( / )"
        ariaLabel="Global search"
      />

      <span className="spacer" />

      <div className="topbar-actions" role="toolbar" aria-label="Topbar actions">
        <button className="icon-btn" type="button" title="Notifications" aria-label="Notifications">
          {/* Bell glyph */}
          <svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true">
            <path
              fill="currentColor"
              d="M8 1.5a3.5 3.5 0 0 0-3.5 3.5v2.379l-.707.707A1 1 0 0 0 4.5 9.5h7a1 1 0 0 0 .707-1.414L11.5 7.379V5A3.5 3.5 0 0 0 8 1.5Zm-1.5 9.5a1.5 1.5 0 0 0 3 0h-3Z"
            />
          </svg>
        </button>
        <button className="icon-btn" type="button" title="Help" aria-label="Help">
          ?
        </button>
        <span className="avatar" aria-label="islamelbanna.mcm@gmail.com">IE</span>
      </div>
    </header>
  );
}
