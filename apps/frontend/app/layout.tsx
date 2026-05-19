// Root layout for the App Router.
// Skeleton only — providers (MSAL, TanStack Query, Theme) will be wired here
// in a follow-up branch. See docs/ROADMAP.md Phase 1.
//
// TODO(phase-1):
//  - <MsalProvider> for Entra ID auth
//  - <QueryClientProvider> for TanStack Query
//  - <ThemeProvider> + design tokens
//  - <TelemetryProvider> for OpenTelemetry web SDK
//  - Strict CSP nonce propagation

import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

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
        {/* TODO(phase-1): replace with full app chrome (nav, tenant switcher, user menu) */}
        {children}
      </body>
    </html>
  );
}
