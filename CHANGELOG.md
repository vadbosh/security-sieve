# Changelog

## 1.0.0 — 2026-10-09

First release as its own repository. Starts from `security-review` of
getsentry/skills (commit 3482d8dd3531), renamed to `security-sieve`.

- **Refutation pass.** Every candidate is checked on its own, in a fresh
  context, and scored 1–10: 8 and above is a finding, 5–7 needs verification,
  below 5 is dropped. A refuter gets the candidate, the refutation step, the
  whole "Do not flag" section and the loaded guides; at most 5 run at a time.
- **Diff mode.** With no target inside a git repository the skill reviews the
  branch against its merge base (`origin/HEAD`, `main`, `master`, `trunk`,
  `develop`), including untracked files, and reports only what the change
  introduces or makes reachable. No base found: it asks instead of reviewing
  an empty range.
- **Tool evidence.** semgrep, trufflehog, gitleaks, osv-scanner, trivy and
  checkov run when already installed; their hits are candidates, never
  findings. Secret scanners run twice, on git history and on the working
  tree. Output goes to a scratch directory and is read through projections,
  so secret values never reach the model: gitleaks runs with `--redact`,
  trufflehog is read through `jq`, and the source lines semgrep and trivy quote
  are dropped the same way; without `jq` those three are skipped.
- **Secrets in git history** are findings even when HEAD no longer has them;
  the fix is rotation first. A report always says whether history was
  scanned.
- **Variant analysis.** A confirmed finding is searched for across the
  repository; variants go through the same refutation.
- **Exclusions.** Denial of service, missing hardening, theoretical races,
  log spoofing, path-only SSRF, prompt text without a reachable tool and the
  rest are excluded outright; one rule for unpinned third-party code; CI
  variables built from event data count as attacker input.
- **Report.** Each finding carries its CWE, its OWASP Top 10:2025 category, an
  exploit scenario, the refutation score and its variants. The posture score
  is a formula.
- **Guides written for this release:** `languages/php.md`,
  `infrastructure/kubernetes.md`, `infrastructure/terraform.md`,
  `infrastructure/ci-cd.md`, `infrastructure/cloud.md`,
  `references/agentic.md` (agent tools, MCP, skills, hooks) and
  `references/threat-modeling.md`.
- **Install.** `install.sh` for Linux and macOS, `install.ps1` for Windows.
  Both warn when trufflehog or gitleaks is missing; on Windows without bash
  the review is basic, and the installer says so.
- **Release checks.** `release.sh verify` checks the index, licenses, pinned
  upstream copies and machine paths; `check` adds tag and installed copies;
  `tag` refuses a dirty tree or a failing `verify`.
- **Licenses.** Apache-2.0 for SKILL.md and our own guides, CC BY-SA 4.0 for
  the reference material copied from upstream, kept byte for byte as pinned in
  `UPSTREAM`.
