// Root layout for the App Router.
//
// Phase 11 replaces the Phase-8 single-page chrome with the enterprise
// `AppShell` (dark navy Sidebar + Topbar wrapping a light content surface).
// Auth providers, MSAL, telemetry, and theme toggle still arrive in Phase 1
// — see docs/PHASE_11_ENTERPRISE_UX.md for the deferred items.

import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import "./globals.css";

import { AppShell } from "@/components/shell/AppShell";

export const metadata: Metadata = {
  title: "AzureLens — Cloud Threat & Compliance Exposure Analyzer",
  description:
    "Continuous, AI-augmented posture, compliance, and live threat-exposure analysis for Azure and Microsoft 365 tenants.",
  robots: { index: false, follow: false }, // private app; disallow indexing
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        {/* TODO(phase-1):
              - <MsalProvider>            Entra ID auth (PKCE)
              - <QueryClientProvider>     TanStack Query
              - <ThemeProvider>           design tokens + dark mode
              - <TelemetryProvider>       OpenTelemetry web SDK
              - Strict CSP nonce propagation per docs/SECURITY_MODEL.md § 3.1
        */}
        <AppShell>{children}</AppShell>
      </body>
    </html>
  );
}
