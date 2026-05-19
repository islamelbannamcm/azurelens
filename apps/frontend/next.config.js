// @ts-check

/**
 * Next.js configuration for AzureLens frontend.
 *
 * Skeleton only — strict security headers, image policy, and i18n
 * will be hardened in a follow-up branch. See docs/SECURITY_MODEL.md
 * § 3.1 for the target frontend security posture (strict CSP,
 * Trusted Types, HSTS, SameSite=Strict, no inline scripts).
 *
 * TODO(phase-1):
 *  - Add `headers()` with strict Content-Security-Policy.
 *  - Add `redirects()` for legacy paths once they exist.
 *  - Wire output: 'standalone' for Azure Container Apps deploy.
 *  - Add Sentry / OpenTelemetry instrumentation hook.
 */
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    // App Router is default in Next 14; no extra flags required for skeleton.
  },
  // TODO(phase-1): enable for Container Apps deployment.
  // output: 'standalone',
};

module.exports = nextConfig;
