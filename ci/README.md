# ci/ — holding directory for the CI workflow

> **Why this file is not yet at `.github/workflows/ci.yml`**
>
> The MCP token used to seed this branch (IslamGitHubWriteServer) does **not** carry the GitHub OAuth `workflow` scope. The GitHub Contents API refuses any write under `.github/workflows/**` without that scope, returning:
>
> > `Resource not accessible by personal access token`
>
> The intended workflow content has therefore been committed to `ci/ci.yml` on this branch so it lives in the repo for review. **To activate CI, a user with `workflow` scope** (or anyone editing through the GitHub web UI) must move it:
>
> ```
> git mv ci/ci.yml .github/workflows/ci.yml
> git commit -m "ci: activate foundation CI workflow"
> git push
> ```
>
> No content changes are required — the YAML is exactly the workflow file specified in `docs/DEVELOPMENT_GUIDE.md`.

This directory will be removed in the same commit that moves the file.
