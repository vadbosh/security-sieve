---
name: security-sieve
description: Security review that reports only exploitable findings — every candidate goes through a separate refutation pass before it is reported. Covers code, a diff or a branch, threat models and CVE triage, infrastructure (Docker, Kubernetes and Helm, Terraform, CI/CD pipelines, cloud IAM) and code that drives AI agents (tools, MCP servers, skills, hooks). Use when asked to "security review", "find vulnerabilities", "audit security", "review this branch/PR for security", "threat model", "is this CVE exploitable", "audit IAM", "review this MCP server".
version: "1.0.1"
allowed-tools: Read Grep Glob Bash Agent
license: LICENSE
---

<!--
Derived from getsentry/skills, skills/security-review (Apache-2.0), with
changes. Reference material in the references/ files listed in UPSTREAM,
languages/python.md, languages/javascript.md and infrastructure/docker.md is
based on the OWASP Cheat Sheet Series (CC BY-SA 4.0):
https://cheatsheetseries.owasp.org/
See LICENSE in this directory for which file is under which license.
-->

# security-sieve

Find security vulnerabilities an attacker can actually exploit, and report
nothing else. The method is two passes: a hunt that collects candidates, and a
refutation pass that tries to break each candidate on its own. Only what
survives the second pass is a finding.

Reviewers, human and model alike, are biased toward seeing bugs and toward
overrating their severity. A report with three real findings is worth more than
one with three real findings among twenty plausible ones: the reader cannot
tell which three.

## Modes

| Request | Mode | Start with |
|---------|------|-----------|
| "review my changes", "this branch", "this PR", no target named inside a git repository with changes | **Diff** | Step 1, diff scope |
| A file, a directory, a whole repository | **Code** | Step 1, code scope |
| Threat model, attack surface, "is this CVE exploitable", dependency triage | **Threat model** | `references/threat-modeling.md` |
| IAM, secrets, Vault, mTLS, Kubernetes, Terraform, CI pipelines | **Infrastructure** | the guide in `infrastructure/` |

Every mode starts with Step 0 — where the report goes, in which format and
language — and ends in the same refutation pass (Step 5) and the same report.

## Scope: research vs. reporting

- **Report on** only the code, diff or configuration the user named.
- **Research** the entire repository to build confidence before reporting.

Before flagging anything, learn from the codebase:

- Where does the input come from? Trace the data flow back to its source.
- Is it validated, sanitised or allowlisted elsewhere?
- How is it configured — settings, config files, middleware?
- What does the framework already protect against?

**Never report on pattern matching alone.** A match is a candidate, not a finding.

## Process

### 0. Ask where the report goes

Before Step 1, ask the user three things **in one dialog**, with the
assistant's structured question tool — `AskUserQuestion` in Claude Code,
`request_user_input` in Codex, `question` in Opencode; where none exists, as a
numbered list the user answers with one line:

| Question | Options | Recommended |
|----------|---------|-------------|
| Where to write the report | outside the repository: `~/security-reviews/<repo>-<YYYY-MM-DD>.<ext>`; a path the user names; chat only | `~/security-reviews/…` |
| Format | `md` (Markdown); `txt` (plain text); `html` (one self-contained file) | `md` |
| Language | the language of the session; English | the language of the session |

- Skip a question the user has already answered in the request.
- **Inside the reviewed repository only if the user chooses it.** A report
  names every weakness and where it is; inside a checkout it is one
  `git add -A` away from being committed, and a public repository publishes it.
- A subagent or a run nobody can answer: use the recommended options without
  asking, and say so in the report's first line.
- Get the date from `date +%F`, not from memory. Make the directory with
  `mkdir -p` and the file readable only by its owner (`chmod 600`).
- **Never overwrite a report.** Several reviews can run at once — parallel
  subagents, a second run on the same repository the same day. Before writing,
  check whether the file exists, and if it does, choose a name that tells the
  reports apart: the scope (`-diff`, `-api`, `-terraform`), the time
  (`-1645`), or a number (`-2`). Pick what a reader of the directory would
  understand; say the final path in the chat.

**Diff mode.** Find the base, then read every change against it:

```bash
base=""
for ref in origin/HEAD origin/main origin/master main master trunk develop; do
    git rev-parse -q --verify "$ref" >/dev/null || continue
    base=$(git merge-base HEAD "$ref") && [ "$base" != "$(git rev-parse HEAD)" ] && break
    base=""
done
echo "base=${base:-NONE}"
git log --oneline "$base"..HEAD                 # what the branch is
git diff --name-only "$base"...HEAD             # committed changes
git diff HEAD --name-only                       # changed, not committed yet
git ls-files --others --exclude-standard        # new files, not tracked yet
```

- `base=NONE` — no default branch was found, or HEAD **is** the default
  branch. Do not run the range commands: with an empty base they print
  nothing and exit 0, which looks like an empty diff. Ask the user for the
  base, or switch to code mode if they meant the current tree.
- All four lists empty — there is nothing to review in diff mode. Say so and
  offer code mode.
- Untracked files are new code: read them in full.

Report only what the change **introduces or makes reachable**: a new sink, a
removed check, a widened permission, a new route to old vulnerable code. An old
vulnerability the diff does not touch goes under "Outside the diff" at the end
of the report, one line each, and never counts toward the score.

**Code mode.** List the entry points first — routes, handlers, CLI arguments,
message consumers, file and network readers. Read outward from them; a sink
nothing reaches is not a finding.

### 2. Load the guides

What kind of code is it?

| Code type | Load | OWASP Top 10:2025 |
|-----------|------|-------------------|
| API endpoints, routes | `authorization.md`, `authentication.md`, `injection.md` | A01, A07, A05 |
| Frontend, templates | `xss.md`, `csrf.md` | A05, A01 |
| File handling, uploads | `file-security.md` | A01 |
| Crypto, secrets, tokens | `cryptography.md`, `data-protection.md` | A04 |
| Data serialisation | `deserialization.md` | A08 |
| Outbound requests | `ssrf.md` | A01 |
| Business workflows | `business-logic.md` | A06 |
| GraphQL, REST design | `api-security.md` | A01 |
| Config, headers, CORS | `misconfiguration.md` | A02 |
| Dependencies, build | `supply-chain.md` | A03 |
| CVEs, SBOM, CVSS, threat model | `threat-modeling.md` | — |
| Error handling, fail-open | `error-handling.md` | A10 |
| Audit, logging | `logging.md` | A09 |
| LLM features, prompt injection, WebSocket | `modern-threats.md` | A05 |
| Agent tools, MCP servers and clients, skills, hooks, plugins | `agentic.md` | — |

All of them live in `references/`.

Then the language and the infrastructure:

| Indicators | Guide |
|------------|-------|
| `.py`, `django`, `flask`, `fastapi` | `languages/python.md` |
| `.js`, `.ts`, `express`, `react`, `vue`, `next` | `languages/javascript.md` |
| `.php`, `laravel`, `symfony`, `composer.json` | `languages/php.md` |
| `Dockerfile`, `.dockerignore`, compose files | `infrastructure/docker.md` |
| Kubernetes manifests, Helm charts and values | `infrastructure/kubernetes.md` |
| `.tf`, `.tfvars`, OpenTofu, Terragrunt | `infrastructure/terraform.md` |
| `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile` | `infrastructure/ci-cd.md` |
| Cloud IAM, secrets managers, mTLS, network, compliance | `infrastructure/cloud.md` |

No guide for the language: use the core references and the framework's own
security documentation.

### 3. Collect tool evidence, if the tools are there

A scanner finds what a reader misses on a large tree, and its output is
reproducible. Run what is **already installed**; never install anything for
the review. Every scanner hit is a **candidate** and goes through Steps 4–5
like any other — most of their output is hardening advice, not an exploit.

Scanner output goes into a scratch directory **outside the repository**, and
is read through the projection in the table, never raw:

```bash
out=$(mktemp -d "${TMPDIR:-/tmp}/security-sieve.$(basename "$PWD").XXXXXX")
echo "$out"             # note the path; delete the directory once the report is written
TH='{detector: .DetectorName, verified: .Verified,
     where: (.SourceMetadata.Data | to_entries[0].value | {file, line, commit})}'
```

Each tool call may start a new shell, so `$out` and `$TH` do not survive
between calls. Write the printed path literally into every later command
(`out=/tmp/security-sieve.api.Ab12Cd; …`) and set `TH` again where it is used.
**Never pass the path through a fixed file** such as `/tmp/out_path`: two
reviews running on one machine overwrite each other's, and one reads the
other's scanner output. Measured: two parallel runs did exactly that.

```bash
# Secrets — trufflehog: history, then the working tree (.git itself excluded)
trufflehog git file://. --no-verification --json > "$out/th-git.ndjson"
trufflehog filesystem . --no-verification --json \
    -x <(printf '%s\n' '(^|/)\.git/') > "$out/th-fs.ndjson"
jq -c "$TH" "$out/th-git.ndjson" "$out/th-fs.ndjson"

# Secrets — gitleaks: history, then the working tree; --redact masks values
gitleaks git --no-banner --redact --report-format json --report-path - . > "$out/gl-git.json"
gitleaks dir --no-banner --redact --report-format json --report-path - . > "$out/gl-dir.json"
jq -c '.[] | {RuleID, File, StartLine, Commit}' "$out/gl-git.json" "$out/gl-dir.json"

# Code, dependencies, infrastructure
semgrep scan --config p/default --metrics=off --json <path> > "$out/semgrep.json"
osv-scanner scan source -r --format json . > "$out/osv.json"
trivy fs --scanners vuln,misconfig --format json . > "$out/trivy.json"
checkov -d . --compact --quiet -o cli > "$out/checkov.txt"
```

| Tool | Finds |
|------|-------|
| `trufflehog`, `gitleaks` | secrets in every commit (`git` mode) and in files not committed yet (`filesystem` / `dir` mode) |
| `semgrep` | code patterns, many languages |
| `osv-scanner` | known-vulnerable dependencies |
| `trivy` | dependencies, IaC |
| `checkov` | Terraform, Kubernetes, Dockerfile, CI |

Rules for these runs:

- **Never read a secret scanner's raw output.** `trufflehog` prints the secret
  itself in `Raw`; `gitleaks` does too unless `--redact` is given. The
  projections above keep the detector, file, line and commit and drop the
  value. A report names where a secret is, never what it is. The skill masks
  values itself and does not rely on any redaction tool of the host.
- **No `jq`, no `trufflehog`.** Without `jq` there is no safe way to read
  `trufflehog` output, so skip it and write "trufflehog skipped: jq not
  installed" in the report. `gitleaks` with `--redact` is safe to read
  directly: `Read` its JSON files.
- **History and working tree are separate runs.** The `git` modes see commits
  only; a key in an untracked or staged file is invisible to them. Run both
  rows of each tool. In a directory that is not a git repository run only the
  working-tree rows: `gitleaks git` there prints "no leaks found" with exit 0
  after scanning 0 commits, which is not evidence of anything.
- **Read `semgrep` and `trivy` JSON without its source quotes.** Both copy the
  matched source lines into their output (`extra.lines`, `Code`), and such a
  line can hold a secret. Read them through
  `jq -c 'walk(if type == "object" then del(.lines, .Code) else . end)'`,
  which removes those fields wherever they are; without `jq`, skip both tools.
- **Check the size before reading** (`wc -c`). Over ~20 KB, read the parts
  that name a rule, a file and a line. `checkov` runs with
  `-o cli --compact`: its JSON is about seven times larger for the same
  findings.
- `trivy` runs without its secret scanner: secrets are the job of the two
  tools above, and its output would carry the values.

**No bash, no scanners.** The commands above are bash. On Windows they run in
Git Bash; where the assistant has only PowerShell, skip this step and write
"Basic review: no scanners (no bash shell)" in the report summary, together
with "Secrets in git history: NOT scanned".

**The secret scanners matter most.** `trufflehog` and `gitleaks` are the only
way the review sees git history: a key deleted three commits ago is invisible
to reading the current files. When neither is installed, say so in the report
summary — "Secrets in git history: NOT scanned" — and recommend installing
them; never let an empty secrets section read as "no secrets".

Two of these talk to the network. `semgrep` downloads its registry rules.
`trufflehog` without `--no-verification` sends every key it finds to the
provider's API to test it — ask the user before turning verification on.

Each tool's flags change between versions; on an error, read its `--help`
instead of guessing. A tool that is missing, or still fails after that, is
skipped: the review goes on without it, and the report's "Tools run" line
names only the tools that produced output.

### 4. Hunt for candidates

For each place that looks wrong, write down a candidate: location, vulnerability
class, the source of the input, the sink, and what you believe an attacker
gains. Do not judge yet; collect.

**Is the input attacker-controlled?**

| Attacker-controlled (investigate) | Server-controlled (usually safe) |
|-----------------------------------|----------------------------------|
| `request.GET`, `request.POST`, `request.args` | `settings.X`, `app.config['X']` |
| `request.json`, `request.data`, `request.body` | `os.environ.get('X')` |
| `request.headers` (most headers) | Hardcoded constants |
| `request.cookies` (unsigned) | Internal service URLs from config |
| URL path segments: `/users/<id>/` | Database content written by admins or the system |
| File uploads (content and names) | Signed session data |
| Database content written by other users | Framework settings |
| WebSocket messages, queue messages from outside | CLI flags of a tool the user runs themselves |
| Content an AI agent reads: web pages, issues, emails, files from others | |

**Does the framework mitigate it?** Check the language guide for
auto-escaping, parameterisation and middleware.

**Is there validation upstream?** Validation before this code, sanitising
libraries (DOMPurify, bleach), allowlists.

### 5. Refute every candidate

This is the step that makes the report trustworthy. Each candidate is checked
**on its own, in a fresh context**:

- where the assistant can start subagents (Claude Code `Agent`, Codex and
  Opencode subagents), start one per candidate — at most **5 at a time**;
- otherwise take them one at a time, and re-read the code for each one
  instead of relying on what you concluded during the hunt.

A subagent starts from nothing and sees only what it is given. Give it, in
full text, not as references to "the sections above":

1. the candidate: location, class, source, sink, claimed gain;
2. this step, Step 5, as written;
3. the whole "Do not flag" section, with exclusions and precedents;
4. the guides loaded for this code in Step 2, or their file paths so it can
   read them;
5. what to return: the one-sentence claim, the exploit scenario, the score,
   and the exclusion that applies if any.

Not the other candidates: a refuter that sees them starts comparing instead of
checking.

The refuter's job is to **break** the candidate, not to confirm it:

1. **Restate the claim** in one sentence: "an unauthenticated user can make the
   server do X by sending Y to Z". A claim that cannot be stated this way is
   not a finding — many false positives collapse here.
2. **Walk the chain** and attack each link: is the source really
   attacker-controlled? Is the path from source to sink reachable — called,
   routed, enabled in this configuration? Does anything on the way validate,
   escape or reject the input? Does the framework neutralise the sink?
3. **Check the exclusions** in "Do not flag" below. A match ends the candidate.
4. **Write the exploit scenario**: who the attacker is, the request or input,
   what happens. If you cannot write it concretely, it is not a finding.
5. **Score** the candidate 1–10 for "this is exploitable as described".

| Score | Outcome |
|-------|---------|
| 8–10 | **Finding** — reported with severity |
| 5–7 | **Needs verification** — reported with the question that would settle it |
| 1–4 | Dropped, not mentioned |

Rationalisations to reject during refutation:

| Thought | Why it does not count |
|---------|----------------------|
| "It could be exploitable if…" | A condition you have not shown to hold is a reason to drop or to ask, not to report. |
| "Better safe than sorry" | A false finding costs the reader trust in every true one. |
| "The pattern is always dangerous" | `eval` of a constant is not RCE. Show the input. |
| "Severity is high, so confidence matters less" | Severity and confidence are separate; a speculative critical is still speculative. |
| "The scanner flagged it" | A scanner reports patterns. Its hit is a candidate like any other. |

### 6. Look for variants

A confirmed finding is evidence of a habit. Search the repository for the same
pattern — the same sink, the same missing check, the same helper used
elsewhere — and send every variant through Step 5. Report variants under the
original finding with their locations; do not repeat the explanation.

### 7. Report

Use the output format below, in the format, language and place chosen in
Step 0. In diff mode, list "Outside the diff" last. Then show the user the
summary block in the chat and the path of the file.

---

## Do not flag

### General

- Test files and fixtures, unless the user asked to review test security.
- Dead code, commented code, and documentation that nothing executes. Files
  an assistant loads as instructions — `SKILL.md`, agent prompts, hook and MCP
  configuration — are code for this review (`references/agentic.md`).
- Values that are constants or server-controlled configuration.
- Code paths behind authentication — note the requirement instead, and still
  report what an authenticated user can do to other users (IDOR, privilege
  escalation).

### Classes excluded outright

These are not reported, whatever their severity would be:

1. Denial of service, resource exhaustion, missing rate limits, memory or CPU
   consumption, regex denial of service. This holds in every mode and every
   guide: a threat model may list availability threats as design notes,
   never as findings.
2. Missing hardening on its own — a header, a flag, a policy that is absent.
   Code is not required to implement every best practice; a finding needs a
   concrete exploit. Unencrypted storage, a missing lock file and missing
   versioning are hardening too, until an attacker has a path to read or
   change the data.
3. Outdated third-party libraries, unless the threat-model mode was asked for
   or the vulnerable function is shown to be called with attacker input.
4. Theoretical race conditions and timing attacks. Report a race only with a
   concrete interleaving and its effect.
5. Memory-safety issues in memory-safe languages.
6. Log spoofing: unsanitised user input written to logs.
7. A missing audit log.
8. SSRF where the attacker controls only the path, not the host or the scheme.
9. Regex injection: untrusted text inside a regular expression.
10. User-controlled text inside an AI prompt, **by itself**. It becomes a
    finding only when the model can then reach a tool with real side effects
    or an exfiltration channel without a gate — `references/agentic.md`.
11. Secrets on disk that are otherwise protected (permissions, encryption, a
    secrets store). Git history is not such protection: a secret committed
    once is readable by everyone who can clone — see "Secrets in code".
12. Unpinned third-party code — an action or an image by tag, a module by
    branch, a dependency by version range — unless its owner is outside the
    organisation **and** the job or workload that runs it holds secrets or
    deploy rights. Then it is a finding, Medium. Every guide follows this one
    rule.

### Precedents

- Environment variables and CLI flags are trusted: an attack that needs to
  control them is not an attack. The exception is a value built from
  attacker-controlled event data — a CI variable set from a pull request
  title or a branch name is attacker input (`infrastructure/ci-cd.md`).
- UUIDs are unguessable.
- React and Angular escape output unless `dangerouslySetInnerHTML`,
  `bypassSecurityTrustHtml` or an equivalent is used.
- Missing permission checks in client-side code are not findings: the server
  enforces them.
- GitHub Actions, shell scripts and notebooks need a concrete path for
  untrusted input — who can trigger the workflow, who supplies the argument —
  before an injection in them is reported.
- Open redirects, tabnabbing and XS-Leaks only at very high confidence.
- Logging secrets in plain text is a finding. Logging URLs and non-sensitive
  data is not.

### Server-controlled values (not attacker-controlled)

| Source | Example | Why it is safe |
|--------|---------|----------------|
| Django settings | `settings.API_URL`, `settings.ALLOWED_HOSTS` | Set via config/env at deployment |
| Environment variables | `os.environ.get('DATABASE_URL')` | Deployment configuration |
| Config files | `config.yaml`, `app.config['KEY']` | Server-side files |
| Framework constants | `django.conf.settings.*` | Not user-modifiable |
| Hardcoded values | `BASE_URL = "https://api.internal"` | Compile-time constants |

**SSRF — not a vulnerability:**
```python
# SAFE: the URL comes from Django settings (server-controlled)
response = requests.get(f"{settings.SEER_AUTOFIX_URL}{path}")
```

**SSRF — a vulnerability:**
```python
# VULNERABLE: the URL comes from the request (attacker-controlled)
response = requests.get(request.GET.get('url'))
```

### Framework-mitigated patterns

| Pattern | Why it is usually safe |
|---------|------------------------|
| Django `{{ variable }}` | Auto-escaped by default |
| React `{variable}` | Auto-escaped by default |
| Vue `{{ variable }}` | Auto-escaped by default |
| Blade `{{ $variable }}` | Auto-escaped by default |
| `User.objects.filter(id=input)` | The ORM parameterises the query |
| `cursor.execute("...%s", (input,))` | Parameterised query |
| `innerHTML = "<b>Loading...</b>"` | Constant string, no user input |

Flag them only when the protection is switched off:

- Django: `{{ var|safe }}`, `{% autoescape off %}`, `mark_safe(user_input)`
- React: `dangerouslySetInnerHTML={{__html: userInput}}`
- Vue: `v-html="userInput"`
- Blade: `{!! $userInput !!}`
- ORM: `.raw()`, `.extra()`, `RawSQL()`, `whereRaw()` with string interpolation

---

## Severity

Severity is set after refutation, for findings only.

| Severity | Impact | Examples |
|----------|--------|----------|
| **Critical** | Direct exploit, severe impact, no authentication needed | RCE, SQL injection reaching data, authentication bypass, a live production secret in code |
| **High** | Exploitable under conditions, significant impact | Stored XSS, SSRF to cloud metadata, IDOR on sensitive data, CI injection from a fork PR |
| **Medium** | Specific conditions, moderate impact | Reflected XSS, CSRF on a state-changing action, path traversal limited to readable files |
| **Low** | Exploitable, minimal impact | Open redirect proven reachable, disclosure of internal hostnames |

Missing headers, verbose errors and weak algorithms with no exploit path are
hardening, not Low findings: they are excluded above.

---

## Quick patterns

Every line below is a **candidate** to trace, not a verdict.

### Usually critical when the input is attacker-controlled
```
eval(user_input)           # any language
exec(user_input)           # any language
pickle.loads(user_data)    # Python
yaml.load(user_data)       # Python (not safe_load)
unserialize($user_data)    # PHP
deserialize(user_data)     # Java ObjectInputStream
shell=True + user_input    # Python subprocess
child_process.exec(user)   # Node.js
```

### Usually high when the input is attacker-controlled
```
innerHTML = userInput              # DOM XSS
dangerouslySetInnerHTML={user}     # React XSS
v-html="userInput"                 # Vue XSS
f"SELECT * FROM x WHERE {user}"    # SQL injection
`SELECT * FROM x WHERE ${user}`    # SQL injection
os.system(f"cmd {user_input}")     # command injection
```

### Secrets in code
```
password = <string literal>
api_key = <string literal with a provider prefix>
AWS_SECRET_ACCESS_KEY = <string literal>
private_key = <PEM block>
```
Confirm it is a real credential, not a placeholder, a test fixture or a public
key. A live production secret is Critical whatever else the report contains.

**A secret in git history is a finding even when HEAD no longer has it.**
Deleting the line in a later commit revokes nothing: every clone, fork and
cache still holds the commit. Three rules for the refutation pass:

- "It is not in the current code" does not lower the score. Report the commit
  and the path where the secret appears.
- "Liveness is not verified" does not lower the score either. The scanners run
  without verification, so treat the secret as live until the user confirms it
  is revoked.
- Severity follows who can read the history: Critical for a production
  credential in a public repository or one shared beyond the key's owners;
  High in a private repository.

The fix is always **rotate or revoke first**. Rewriting history afterwards is
optional and does not replace rotation.

### Check the context first
```
# SSRF - only if the URL comes from user input
requests.get(request.GET['url'])     # FLAG: user-controlled URL
requests.get(settings.API_URL)       # SAFE: server-controlled config
requests.get(f"{settings.BASE}/{x}") # CHECK: is 'x' user input? path only → excluded

# Path traversal - only if the path comes from user input
open(request.GET['file'])            # FLAG: user-controlled path
open(settings.LOG_PATH)              # SAFE: server-controlled config
open(f"{BASE_DIR}/{filename}")       # CHECK: is 'filename' user input?

# Open redirect - only if the URL comes from user input
redirect(request.GET['next'])        # FLAG: user-controlled redirect
redirect(settings.LOGIN_URL)         # SAFE: server-controlled config

# Weak crypto - only if used for security
hashlib.md5(file_content)            # SAFE: checksums, caching
hashlib.md5(password)                # FLAG: password hashing
random.random()                      # SAFE: non-security uses
random.random() for token            # FLAG: tokens need the secrets module
```

---

## Posture score

After the findings, compute a score `1-10` for the reviewed code or diff by
this formula — do not adjust it by feel. The same findings always give the
same score.

1. Any **Critical** finding: the score is `1` when there are two or more of
   them or one is a live production secret (in code or in git history),
   otherwise `2`. Stop here.
2. Otherwise: `10 − 4 × High − 1.5 × Medium − 0.5 × Low`, rounded down, and
   never below `3`.

| Findings | Score |
|----------|-------|
| none | 10 |
| 1 Low | 9 |
| 1 Medium, or 4 Low | 8 |
| 2 Medium, or 1 Medium + 2 Low | 7 |
| 1 High | 6 |
| 3 Medium | 5 |
| 1 High + 1 Medium | 4 |
| 2 High or more | 3 |

- Count a finding once, with its variants.
- Needs-verification items and findings outside the diff do not count.

The score is for triage at a glance. It is not CVSS.

---

## Output format

```markdown
## Security review: [file, component or branch]

### Summary
- **Scope**: [files / diff base..HEAD / repository]
- **Findings**: X (Y Critical, Z High, ...)
- **Posture score**: N/10
- **Needs verification**: K
- **Tools run**: [semgrep, gitleaks git+dir, trufflehog git+filesystem, ... / none installed; name any tool skipped and why]
- **Secrets in git history**: [scanned by trufflehog / gitleaks — or "NOT scanned: neither trufflehog nor gitleaks is installed"]
- **Secrets in uncommitted files**: [scanned — or "NOT scanned"]

### Findings

#### [VULN-001] [Vulnerability class] (Severity)
- **Location**: `file.py:123`
- **Class**: CWE-89, OWASP A05:2025 Injection
- **Refutation score**: 9/10
- **Issue**: [what is wrong]
- **Exploit scenario**: [who, which input, what happens]
- **Evidence**:
  ```python
  [vulnerable code]
  ```
- **Fix**: [the change, with code]
- **Variants**: `other.py:45`, `third.py:78` (or "none found")

### Needs verification

#### [VERIFY-001] [Potential issue]
- **Location**: `file.py:456`
- **Refutation score**: 6/10
- **Question**: [what would settle it, and how to check]

### Outside the diff
- `old.py:12` — [one line] (diff mode only)
```

No findings: write "No exploitable vulnerabilities found." and list what was
reviewed and which tools ran, so the reader knows what the empty result covers.

### Formats and language

The template above is Markdown. For the other formats keep the same sections,
in the same order, with the same fields:

- **`txt`** — plain text, no Markdown markup: headings in capitals with a line
  of `=` under them, fields as `Location: …`, code indented by four spaces,
  lines up to 80 characters.
- **`html`** — one self-contained file: inline `<style>`, no JavaScript, no
  external fonts, images or scripts, so it opens offline and can be mailed.
  Escape every quoted piece of code (`&lt;`, `&gt;`, `&amp;`); a finding that
  quotes an XSS payload must not execute in the report. Severity may be
  coloured; the text must still say it.

**Language.** Headings, field names and prose follow the chosen language.
Never translate what the reader must match exactly: paths, `file:line`, code,
commands, CWE and OWASP identifiers, commit hashes, tool names and their
messages. The labels VULN-001, VERIFY-001 stay as they are.

**No secret values in any format.** A report names where a credential is —
file, line, commit, detector — never its value, not even part of it.

---

## Reference files

### Core vulnerabilities (`references/`)

| File | Covers |
|------|--------|
| `injection.md` | SQL, NoSQL, OS command, LDAP, template injection |
| `xss.md` | Reflected, stored, DOM-based XSS |
| `authorization.md` | Authorization, IDOR, privilege escalation |
| `authentication.md` | Sessions, credentials, password storage |
| `cryptography.md` | Algorithms, key management, randomness |
| `deserialization.md` | Pickle, YAML, Java, PHP deserialisation |
| `file-security.md` | Path traversal, uploads, XXE |
| `ssrf.md` | Server-side request forgery |
| `csrf.md` | Cross-site request forgery |
| `data-protection.md` | Secrets exposure, PII, logging |
| `api-security.md` | REST, GraphQL, mass assignment |
| `business-logic.md` | Race conditions, workflow bypass |
| `modern-threats.md` | Prototype pollution, LLM prompt injection, WebSocket |
| `agentic.md` | Agent tools, MCP servers and clients, skills, hooks, plugins |
| `misconfiguration.md` | Headers, CORS, debug mode, defaults |
| `error-handling.md` | Fail-open, information disclosure |
| `supply-chain.md` | Dependencies, build security |
| `threat-modeling.md` | STRIDE, attack surface, CVE research, SBOM/CVSS triage, remediation plan |
| `logging.md` | Audit failures, log injection |

### Language guides (`languages/`)

| File | Covers |
|------|--------|
| `python.md` | Django, Flask, FastAPI |
| `javascript.md` | Node, Express, React, Vue, Next.js |
| `php.md` | Laravel, Symfony, plain PHP |

### Infrastructure (`infrastructure/`)

| File | Covers |
|------|--------|
| `docker.md` | Container images and runtime |
| `kubernetes.md` | Pod security, RBAC, secrets, ingress, Helm |
| `terraform.md` | IAM, network exposure, state and secrets in HCL |
| `ci-cd.md` | GitHub Actions, GitLab CI, Jenkins |
| `cloud.md` | IAM policies, secrets managers and Vault, service TLS, network exposure |
