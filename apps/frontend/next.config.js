// @ts-check

/**
 * Next.js configuration for AzureLens frontend.
 *
 * Phase 9 enables `output: "standalone"` so the Dockerfile can copy the
 * minimal self-contained server (and only the needed node_modules) into
 * the runtime image — see apps/frontend/Dockerfile.
 *
 * Strict security headers (CSP, HSTS, X-Frame-Options, Trusted Types, etc.)
 * arrive in Phase 1 once Front Door / APIM ingress is in front of the app.
 * See docs/SECURITY_MODEL.md § 3.1 for the target frontend posture.
 *
 * TODO(phase-1):
 *  - Add `headers()` with strict Content-Security-Policy.
 *  - Add `redirects()` for legacy paths once they exist.
 *  - Add Sentry / OpenTelemetry instrumentation hook.
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,

  // Standalone output bundles a minimal Node server + only the modules used
  // by the running app, producing a far smaller container.
  output: "standalone",

  experimental: {
    // App Router is default in Next 14; no extra flags required.
  },
};

module.exports = nextConfig;
