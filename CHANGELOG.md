# Changelog

## 1.2.0 — 2026-10-09

- **Scanners run in the background in Claude Code.** Step 3 starts them in one
  background call right after Step 0, and the model reads code meanwhile. On a
  .NET repository of 1890 commits the scanners took 61 s of a 465 s review;
  the hunt took 155 s, so all of them now finish while the model reads. Codex
  and Opencode still run them one after another.
- **The refuter brief carries the secrets rules.** The `awk` line in Step 5
  stopped at `## Severity` and left out "Secrets in code": git history,
  liveness, severity by who can read the repository. A refuter checking a
  secret worked without them.
- **`checkov` runs with `--skip-framework secrets`.** Its secret checks repeated
  the `trufflehog` and `gitleaks` hits; without them the run took 7 s instead
  of 12 s on the same repository.
- Not adopted: refuters on a faster model. Measured on the same four
  candidates, Sonnet confirmed the same findings but took 57 s against 54 s
  for the slowest refuter, so the review did not get faster.

## 1.1.1 — 2026-10-09

- **`references/injection.md` line 235 works in GNU grep.** The upstream pattern
  `"\\.query\\(.*\\+"` failed with "Unmatched ( or \(": in a basic regular
  expression `\(` opens a group. It now reads `'\.query(.*+'`. The file is a
  CC BY-SA copy, so the change is recorded in `NOTICE` and its checksum in
  `UPSTREAM` is updated. The other grep lines of the copied guides were run on
  fixtures; none else fails.

## 1.1.0 — 2026-10-09

- **A C# / ASP.NET Core guide**, `languages/csharp.md`: object-level
  authorization (a class-level `[Authorize]` only authenticates), caller-supplied
  tenant ids, anonymous token endpoints, ADO.NET / EF Core / Dapper injection,
  deserialisation, XML, `Path.Combine`, redirects, Razor and Blazor output, JWT
  validation, secrets in `appsettings*.json` and publish profiles.
- **Lessons from the first two real reviews** (an ASP.NET Core API, a Terraform
  EKS repository):
  - A secret's severity follows who can read the repository, in its files and
    its history alike: Critical when public or shared, High when private. The
    severity table said "a live production secret in code" is Critical and
    contradicted it.
  - Step 3 groups scanner hits by detector and file first (one repeated
    connection string gave 1,500 lines), skips `.terraform/`, `node_modules/`,
    `vendor/`, `bin/`, `obj/` in the working tree but not in history, keeps
    stderr out of the results, and says a non-zero exit means findings.
  - JWT hits are triaged by their `exp` claim, read without printing the token.
  - The refuter brief (Step 5 and "Do not flag") can be passed as a file.
  - Variants that differ only by place may be listed without their own
    refuter.
  - The report has a "Not assessable from the repository" section.
- **Step 0: the skill asks where the report goes, in which format and
  language** — one dialog: `~/security-reviews/<repo>-<date>`, a path or chat
  only; `md`, `txt` or one self-contained `html`; the session's language or
  English. Inside the reviewed repository only if the user chooses it; an
  existing report is never overwritten — parallel runs choose distinct names.
  A run nobody can answer uses the defaults and says so.
- **The scanner scratch directory is named per repository and never handed
  over through a fixed file.** Each tool call may start a new shell, and two
  reviews on one machine passed the path through the same `/tmp` file: one
  read the other's `checkov` output. `mktemp -d` now gets a
  `security-sieve.<repo>.XXXXXX` template, and Step 3 says to write the
  printed path into later commands.

## 1.0.1 — 2026-10-09

- **`AGENTS.md`, `CLAUDE.md` and `kb/` are no longer in the repository.** They
  are instructions and notes for whoever works on a checkout with an
  assistant, not part of what the skill ships, and 1.0.0 committed the first
  two by mistake. `.gitignore` now keeps assistant artefacts and work notes
  out, as in the author's other repositories.

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
