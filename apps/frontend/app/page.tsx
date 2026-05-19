// Landing page placeholder.
//
// In Phase 1 this becomes the Executive Overview dashboard for authenticated users
// and a marketing/onboarding entry for anonymous users.
//
// TODO(phase-1):
//  - Auth-gate: if signed in, render <ExecutiveOverview />, else render <Onboarding />.
//  - Fetch tenant scores via /api/v1/scores/overview.
//  - Show top 5 prioritized findings + live campaign exposure summary.

export default function HomePage() {
  return (
    <main
      style={{
        fontFamily:
          "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif",
        padding: "3rem",
        maxWidth: "720px",
        margin: "0 auto",
      }}
    >
      <h1>AzureLens</h1>
      <p>
        <strong>Cloud Threat &amp; Compliance Exposure Analyzer</strong> — skeleton.
      </p>
      <p>
        This is the Phase 0/1 placeholder. Authentication, tenant selection, and
        dashboards will be implemented in subsequent feature branches. See{" "}
        <code>docs/ROADMAP.md</code> for milestones.
      </p>
    </main>
  );
}
