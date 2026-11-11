# .github

Ported from dedens `.github/AGENTS.md` at v0.1.0-131-gfd00747.

- Shared workflows come from `spnngl/.github` at `@main`. Third-party actions are pinned by full SHA with a `# vX` comment, and images by digest.
- A tool version carries a `# renovate:` comment. The shared Renovate regex reads only `KEY: "version"` lines, so `taiki-e/install-action` takes `tool@${{ env.TOOL_VERSION }}` from a job `env`. A tool in `build/Containerfile` too keeps the same `depName` in both (D58).
- Every workflow opens with a comment saying what it runs and when, sets `permissions: {}` and grants per job, and has a `concurrency` group that cancels only pull request runs. Every job running steps has `timeout-minutes`; every checkout has `persist-credentials: false`.
- `ci.yml`'s `required` is the one check the `main` ruleset requires (D48). A new `ci` job joins `required.needs` and its result check.
- `actionlint` and `zizmor` lint these files (`lint.yml`); run both locally before pushing.
