// Root layout for the App Router.
//
// Phase 8 wires the basic app chrome (brand header + main container) and
// imports global styles. Auth providers, MSAL, tenant switcher, telemetry
// providers, and theme toggle arrive in Phase 1.

import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";

import "./globals.css";

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
        <header className="app-header">
          <div className="brand">
            <span className="brand-mark">AzureLens</span>
            <span className="brand-sub">
              Cloud Threat &amp; Compliance Exposure Analyzer
            </span>
          </div>
          <div className="app-header-meta">Demo mode · Contoso Demo</div>
        </header>
        <main className="app-main">{children}</main>
      </body>
    </html>
  );
}
