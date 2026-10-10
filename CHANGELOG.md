# Changelog

## 1.8.2 — 2026-10-10

- Documentation caught up with 1.7.0–1.8.1. README and `docs/guide.*` said
  the skill asks three questions; above 500 source files it asks four. The
  guides now also describe the parts mode, refuters on the session's model,
  the narrow re-run of a stopped refuter, the refutation limit of 12,
  configuration files read by key, the Coverage, "Unverified candidates" and
  "Not covered" parts of the report, and how two reports are merged. The
  skill itself is unchanged.

## 1.8.1 — 2026-10-10

- **A refuter stopped early is asked again, once, in other words.** The
  model provider's safety system ended 2 of 11 refuters in one review of a
  Spring service, and the session then confirmed those candidates on its own
  reading. Step 5 now starts one new refuter with a narrow brief — questions
  of fact about the code, each answered with a `file:line` quote, no attack
  wording, no scenario, no payload — and scores the candidate from the
  answers. Stopped twice, the candidate goes under "Needs verification";
  it is never confirmed on the session's own reading alone. Checked: on one
  of the two stopped candidates the narrow brief gave an answer enough for a
  verdict, for USD 0.65. Not shown: that it avoids the stop in a long
  session — a short run on its own was not stopped with either wording.

## 1.8.0 — 2026-10-10

- **`scripts/modules.sh` counts the source files and lists the modules.**
  Groups of at most 500 files, split down the directory tree until none is
  larger; above 500 it also prints the measured cost of a review that size
  as `say-to-user:` lines. Written as rules in prose, the module list came
  out as "src 3599" and "server 3473", and two Codex runs of three dropped
  the cost from the question. Bash 3.2 and busybox awk compatible
  (`index(s, "")` is 0 there).
- **"Review the whole repository" no longer skips the scope question**: it
  names the target, not the way to review it.
- **For important code the scope question advises two separate reviews**
  — one pass and in parts — and a merge of their reports. SKILL.md now says
  how to merge two finished reports. A single run doing both was built and
  tried on 3607 Java files and dropped: it cost USD 80 and confirmed 6, with
  20 candidates left unverified, against 17 and 16 confirmed by the two
  separate runs for USD 99 together.
- **Four upstream guides read as credentials no more**:
  `references/injection.md` 185, `ssrf.md` 305–306, `supply-chain.md` 149,
  `misconfiguration.md` 150, 156, 160 (F240). The guard refused to print
  them, which in Codex is the only way to read a file. Recorded in `NOTICE`
  and `UPSTREAM`.
- Measured in that last run: with the rule that configuration files are read
  by key (1.7.0) and env2hell 0.13.18, `gitleaks` found no secret value in
  the session's transcript; the two earlier runs left 10 and 15.

## 1.7.1 — 2026-10-10

- `languages/python.md` line 150: the example `app.secret_key = '…'` now
  holds `'dev'`. Masking tools read the old 9-letter literal after a
  `secret_key` label as a credential, and from env2hell 0.13.18 the guard
  refused to print the guide, which in Codex is the only way to read it. The
  file is an upstream copy: the change is recorded in `NOTICE` and its sum in
  `UPSTREAM`.

## 1.7.0 — 2026-10-10

- **Java guide: `languages/java.md`.** Spring Boot, Spring Security,
  JPA/Hibernate, JDBC, MyBatis, Servlets; Kotlin on Spring reads the same.
  No ready guide existed in this form: getsentry/skills has none, and the
  Trail of Bits Java notes cover the language, not Spring, so they are
  linked. Written against a real Spring Boot 2.2 service of 3607 source
  files. What that code taught it: where the caller's identity comes from
  when Spring Security is not used, `@ModelAttribute` filled from a request
  parameter of the same name, placeholder defaults (`${key:value}`) as
  secrets scanners miss, an authorisation inventory for Spring handlers and
  what to do when the checks live in services, EL injection through Bean
  Validation messages, hand-made quote escaping on MySQL, `@Cacheable` that
  skips an ownership check. Every grep in the guide was run on that code;
  every one names its path, because `rg` without one reads a piped stdin.
- **Large repositories: a scope question in Step 0.** Above 500 source
  files the skill says what a review of that size took — measured, with the
  date — and offers parts, selected modules, the whole repository, or the
  branch's changes. README carries the same numbers in a note.
- **Parts mode.** A map of modules, trust nodes and the guide's sink hits
  for the whole repository, one pass per module, a pass over the seams,
  refutation of the strongest 12 candidates, and a report that lists the
  unverified candidates and what was not covered. Tried on the same code:
  33 minutes and USD 57 against 27 minutes and USD 42 for one pass; each
  confirmed holes the other missed. The first try ended without a report —
  45 candidates, a stop to ask in a run nobody answered, and the sink
  sweep cut short as a part of its own — and the rules for all three came
  from it.
- **Configuration files are read by key, never printed**, not even through
  a host's masking filter. Both test runs printed `application.yaml`, and
  keys from it reached their transcripts.

## 1.6.1 — 2026-10-10

- The 1.3.3 entry of this changelog quoted the two guide examples that had
  looked like secrets, so the same secrets hook refused to print
  `CHANGELOG.md` itself. The entry now describes those examples in words;
  `secrets-redact` finds 0 values in the file. The skill is unchanged.

## 1.6.0 — 2026-10-10

- **`scan.sh` opens with a summary that the model pastes as it is.** In 1.5.1
  the model was asked to show the `tool` and `ran` lines verbatim; it retold
  them in one sentence and lost which run had failed. The script now prints a
  few lines between two `━━━` bars — `+ ran`, `- FAILED`, `- skipped`,
  `- missing`, `- no git` — and writes them to `<out>/summary.txt`. Step 3
  asks for them in a `diff` code block, where a scanner that ran shows green
  and a failure red. At a terminal the script colours them itself.

## 1.5.3 — 2026-10-09

- README: a note on Windows, with links. The scanners exist there —
  trufflehog `windows_*` archives, gitleaks through `winget`, checkov and
  semgrep through `pip` (semgrep runs natively) — and `scripts/scan.sh` runs
  them in Git Bash when Git for Windows is installed. Without Git Bash the
  review stays basic.

## 1.5.2 — 2026-10-09

- **Refuters run on the session's model in Claude Code.** With
  `CLAUDE_CODE_SUBAGENT_MODEL=sonnet` in the settings, every refuter of an
  Opus review ran on Sonnet without anyone choosing it, and Sonnet's
  safeguards stopped one of them halfway. Step 5 now sets `model` on each
  refuter to the session's own model — an explicit parameter wins over the
  configured default — and says what to do when a refuter still fails.

## 1.5.1 — 2026-10-09

- **The scanner status lines reach the chat.** `scan.sh` printed which tools
  ran, but Claude Code folds command output to a few lines and the model did
  not repeat them, so the user saw nothing. Step 3 now asks for the `tool`,
  `ran` and `skip` lines in a code block as soon as the script finishes.

## 1.5.0 — 2026-10-09

- **Step 3 is a script: `scripts/scan.sh <repo-dir>`.** It lists the
  installed scanners, runs every one of them every time, and prints the tool
  list, one status line per run (`rc`, seconds, errors found in the log) and
  the grouped projections — detector or rule, file, line, commit, never a
  value or a source line. Before, the model ran fifteen commands from the
  text and could skip some; a rule in prose is not a guarantee. Without `jq`
  it skips trufflehog, semgrep and trivy, as before. Bash 3.2 compatible.
  Tested on a .NET repository: six tools run, two reported missing, no secret
  value in the output.

## 1.4.2 — 2026-10-09

- **Step 3 starts by listing the installed scanners** with `command -v`, and
  the report's "Tools run" line is built from that list and the logs. Before,
  a missing tool was found out only by a failed command, and a `pipx` install
  in a `~/.local/bin` absent from the assistant's `PATH` looked the same as
  no install at all.

## 1.4.1 — 2026-10-09

- `docs/guide.en.md` and `docs/guide.ru.md` catch up with 1.3.2–1.4.0: the
  authorisation inventory at the start of the hunt, the assessment notice
  that opens every report, and the scratch directory deleted after the report.

## 1.4.0 — 2026-10-09

- **Every report opens with an assessment notice**, under the title, in every
  format and language: it is a model's assessment, not a final verdict; a
  person checks each finding against the code and the deployment before
  anything is fixed, rotated, published or sent on; what the report does not
  mention was not proven safe. A report is forwarded without the README.

## 1.3.9 — 2026-10-09

- **The CAUTION block says the report is an assessment, not a final
  verdict.** A person checks every finding against the code and the
  deployment before anything is fixed, rotated, published or sent to a
  client, and what the report does not mention is not checked.

## 1.3.8 — 2026-10-09

- **The README opens with a red CAUTION block: the model decides what the
  review finds.** On one API with 7 confirmed vulnerabilities, Claude Opus
  found 5, GPT-6 found 5 others in part, GPT-5 and GPT-5.6 found 2–3 and
  missed every cross-customer bug. The block says to use the strongest model
  at its highest reasoning level, and two models for code that matters.

## 1.3.7 — 2026-10-09

- **A report never replaces another: Step 0 gives the command.** The rule
  was prose, and a Codex run on GPT-5.6 wrote its 7 KB report over a 36 KB
  one from GPT-6 with the same name. Step 0 now has a three-line loop that
  adds `-2`, `-3`, … to the name until it is free, in the same call that
  writes the file. Tested in bash and in the `bash:3.2` image.

## 1.3.6 — 2026-10-09

- **A switched session names the right model.** A Codex session opened on
  GPT-6 and switched to GPT-5.6 kept both system instructions in its context;
  the skill said "the review runs on GPT-6" while every turn ran on GPT-5.6.
  Step 0 now takes the last model the context names, and says it is not
  certain when it cannot tell.

## 1.3.5 — 2026-10-09

- **Step 4 starts with an authorisation inventory** where objects have
  owners: every entry point that takes an object id, and whether the code ties
  that id to the caller. Four reviews of one multi-tenant API by three models
  each missed some of its seven confirmed holes; the two cross-tenant ones the
  strongest run missed were found by such a table. The step is in `SKILL.md`,
  so it applies to every language.
- **The C# guide gives the command for the inventory**: one line per
  controller action with its route, whether it takes an id, and how many
  tenant checks its body has. On that API it listed all six known places.

## 1.3.4 — 2026-10-09

- **Web searches name only public things.** A Codex review searched the web
  for how NLog loads `nlog.config` on Linux — a good check, and a query that
  leaves the machine whatever the sandbox says. Step 3 and the refuter brief
  now allow a library, a version, an API or a CVE id in a query, and never
  code, paths, hosts, routes, configuration keys or values from the
  repository.

## 1.3.3 — 2026-10-09

- **Guide examples no longer read as credentials.** A secrets hook blocked
  Codex from reading `languages/csharp.md`, `infrastructure/kubernetes.md` and
  `infrastructure/ci-cd.md` because example code looked like a secret:
  a `token` variable assigned from a method call, a password in a URL, a
  base64 value, an `http_tokens` key with a quoted value. The examples say
  the same thing in a form a redactor does not flag; `secrets-redact` finds 0
  values in the three files.
  The copies from Sentry are left as they are.
- **The C# guide covers fallback literals**: `cfg["XSecret"] ?? "…"` or a
  ternary ending in `: "…"`. A real review found such a key that neither
  `trufflehog` nor `gitleaks` reported. The guide gives an `rg -o` command
  that prints the file and line but not the value.

## 1.3.2 — 2026-10-09

- **Step 0 checks that the report directory is writable**, right after the
  answer and before any review work. Codex in `workspace-write` writes only
  to its working directory, `/tmp` and `writable_roots`; it found out about
  `~/security-reviews` only at the end and put the report in `/tmp`. Now the
  skill says so at once and offers `/tmp/security-reviews/` or another path.
  The guide shows the `writable_roots` line for `~/.codex/config.toml`.
- **`trufflehog` runs with `--no-update`.** In the Codex sandbox it tried to
  replace its own binary, failed with "cannot move binary" and exited with
  empty output. Step 3 now also says that an empty output file is not
  "nothing found" until its log says so.
- **Step 7 deletes the scratch directory** as an action of its own. The
  instruction used to be a code comment, and Codex left the directory behind.
- The README block on models adds a full Codex run on GPT-5: two of the four
  vulnerabilities found, both cross-customer data access bugs missed.

## 1.3.1 — 2026-10-09

- **The model line is one plain sentence.** In Codex it came out as
  shorthand: "сравнение refutation на Sonnet дало те же findings…". Step 0
  now gives the sentence to say, with no terms from the skill; the details of
  the measurement stay in the README.
- **Codex in its default mode gets a numbered list.** It has no
  `request_user_input` there (Plan mode only), and its system prompt forbids
  multiple-choice text, so the three questions had been merged into one
  sentence the user could not answer. Step 0 now shows the list with every
  option and an example answer, with the repository name and date filled in.
  Tested with `codex exec` on codex-cli 0.162.0.
- The README block on models says in plain words what Sonnet did differently.

## 1.3.0 — 2026-10-09

- **The skill names the model that runs the review.** Step 0 starts with one
  line in the chat: the model, and that the method was measured on Claude
  Opus. On another model it adds what one Sonnet comparison showed and that
  other models were not measured. The report summary has a new field,
  **Model**.
- **The README says that the model matters**, in an IMPORTANT block: Sonnet,
  compared once on the refutation step, confirmed the same findings but
  missed one detail and scored one candidate 6 instead of 4.

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
