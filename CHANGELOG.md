# Changelog

## 1.0.0 — 2026-10-09

First release as its own repository. Starts from `security-review` of
getsentry/skills (commit 3482d8dd3531) as it was kept in a local
configuration, renamed to `security-sieve`.

- **Refutation pass.** Every candidate is checked on its own, in a fresh
  context — one subagent per candidate where the assistant has them — and
  scored 1–10. 8 and above is a finding, 5–7 needs verification, below 5 is
  dropped.
- **Diff mode.** With no target inside a git repository the skill reviews the
  branch against its merge base, and reports only what the change introduces
  or makes reachable. Older issues go to "Outside the diff".
- **Tool evidence.** semgrep, trufflehog, gitleaks, osv-scanner, trivy and
  checkov are run when already installed; their hits are candidates, never
  findings. Nothing is installed, and trufflehog runs without verification
  unless the user agrees.
- **Variant analysis.** A confirmed finding is searched for across the
  repository; variants go through the same refutation.
- **Exclusions.** Denial of service, missing hardening, theoretical races,
  log spoofing, path-only SSRF, prompt text without a reachable tool and the
  rest are excluded outright, with precedents for trusted inputs.
- **Report.** Each finding carries its CWE, its OWASP Top 10:2025 category, an
  exploit scenario, the refutation score and its variants.
- **New guides.** `languages/php.md`, `infrastructure/kubernetes.md`,
  `infrastructure/terraform.md`, `infrastructure/ci-cd.md`,
  `references/agentic.md` (agent tools, MCP, skills, hooks).
- **Index.** Lists only files that exist; `release.sh check` keeps it so.
- **Licenses.** Apache-2.0 for SKILL.md and our own guides, CC BY-SA 4.0 for
  the reference material copied from upstream, which stays byte for byte as
  pinned in `UPSTREAM`.
