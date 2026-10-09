# security-sieve

A security-review skill for Claude Code, Codex and Opencode that **reports only
vulnerabilities an attacker can exploit**. It reviews code, a branch diff,
infrastructure configuration and code that drives AI agents.

The review runs in two passes:

1. **Hunt.** The reviewer reads the code and collects candidates. Each one
   names a location, the input, the sink, and what an attacker gains.
2. **Refutation.** Each candidate is checked again on its own, in a fresh
   context, by a reviewer whose job is to break it. It restates the claim in
   one sentence, attacks each link from input to sink, and writes the exploit
   scenario. Then it scores the candidate from 1 to 10.

A candidate scored 8 or higher is reported as a finding. A score of 5–7 goes to
"Needs verification", with the question that would settle it. Anything lower is
dropped and not mentioned.

Why two passes: reviewers, human and model alike, tend to see bugs and to
overrate them. Say a report has three real findings among twenty plausible
ones. The reader cannot tell which three are real, so the report is worth less
than one with the three alone.

```
you:    /security-sieve
skill:  Diff mode: 14 files changed since merge base 3f2a91c.
        Tools found: semgrep, trufflehog. 9 candidates.
        Refutation: 2 findings, 1 needs verification, 6 dropped.
        ## Security review: feature/upload-api
        [VULN-001] Path traversal (High) — api/upload.py:48, CWE-22 …
```

## What it reviews

| You ask | Mode | What happens |
|---|---|---|
| "review my changes", or no target inside a git repository | Diff | Reads the branch against its merge base. Reports what the change introduces or makes reachable. Older issues are listed under "Outside the diff" and do not count toward the score |
| a file, a directory, a repository | Code | Starts from the entry points (routes, handlers, CLI arguments, consumers) and follows the data to the sinks |
| a threat model, "is this CVE exploitable" | Threat model | STRIDE, attack surface, CVE and dependency triage |
| IAM, Kubernetes, Terraform, CI pipelines | Infrastructure | The guide for that kind of configuration |

Guides the skill loads by file type:

- **Languages:** Python (Django, Flask, FastAPI), JavaScript and TypeScript
  (Node, Express, React, Vue, Next.js), PHP (Laravel, Symfony).
- **Infrastructure:** Docker, Kubernetes and Helm, Terraform, CI/CD (GitHub
  Actions, GitLab CI, Jenkins), cloud IAM, secrets and mTLS.
- **Vulnerability classes:** injection, XSS, authorization, authentication,
  cryptography, deserialisation, file handling, SSRF, CSRF, data protection,
  API design, business logic, misconfiguration, error handling, supply chain,
  logging.
- **AI agents:** tools with side effects, MCP servers and clients, skills,
  hooks and plugins.

## What it does not report

Some classes are excluded outright, whatever their severity would be:

- denial of service;
- missing hardening with no exploit;
- outdated libraries with no reachable vulnerable call;
- theoretical race conditions;
- log spoofing;
- SSRF that controls only the path;
- user text inside an AI prompt, unless the model can then reach a tool with
  real side effects.

Environment variables and CLI flags count as trusted input.

SKILL.md lists every exclusion and precedent, so you can see why a candidate
was dropped.

## What it needs

Only the assistant is required. Everything else adds coverage, and the skill
works without it.

| Tool | Required | Used for | If it is missing |
|---|---|---|---|
| Claude Code, Codex or Opencode | yes | runs the skill | — |
| `git` | for diff mode | finding the merge base and the diff | Diff mode is not available. Code mode still works on files and directories |
| `jq` | for `trufflehog` | reading `trufflehog` output without the secret values in it | `trufflehog` is skipped; `gitleaks` still runs |

The skill masks secret values itself: `gitleaks` runs with `--redact`, and
`trufflehog` output is read through a `jq` projection that drops the value. It
does not depend on any redaction tool on your machine.

> [!IMPORTANT]
> **Install `trufflehog` and `gitleaks`.** They are the only way the review
> sees git history. A key deleted three commits ago is still in every clone,
> and reading the current files will not find it. Without either scanner the
> report says "Secrets in git history: NOT scanned".
>
> ```bash
> brew install trufflehog gitleaks
> ```
>
> Other systems: the release pages of
> [trufflehog](https://github.com/trufflesecurity/trufflehog/releases) and
> [gitleaks](https://github.com/gitleaks/gitleaks/releases).

The skill runs without the scanners, but with less coverage. It runs the ones
already on `PATH`, with the command shown, and never installs one:

| Scanner | Command the skill runs | Adds | If it is missing |
|---|---|---|---|
| [`semgrep`](https://semgrep.dev/docs/getting-started/) | `semgrep scan --config p/default --metrics=off --json <path>` | pattern matches across many languages | The model reads the code from the entry points itself; on a large tree it may miss a sink far from them |
| [`trufflehog`](https://github.com/trufflesecurity/trufflehog) | `trufflehog git file://. --no-verification --json` | secrets in the files and in the whole git history | Secrets are found only in the files the model reads. A key deleted in an old commit is not seen |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | `gitleaks git --no-banner --report-format json --report-path - .` | the same as `trufflehog`, with other rules | Same as above. One of the two is enough |
| [`osv-scanner`](https://google.github.io/osv-scanner/) | `osv-scanner scan source -r --format json .` | known-vulnerable dependency versions from lockfiles | Dependency CVEs are not listed. In code mode they are excluded anyway unless a vulnerable call is reachable; threat-model mode loses its dependency list |
| [`trivy`](https://trivy.dev/) | `trivy fs --scanners vuln,secret,misconfig --format json .` | dependencies, secrets and IaC misconfiguration in one run | Covered in part by the others; without any of them, IaC is reviewed from the guides alone |
| [`checkov`](https://www.checkov.io/) | `checkov -d . --compact --quiet -o json` | policy checks for Terraform, Kubernetes, Dockerfiles and CI | Terraform and Kubernetes are reviewed from the guides alone |

The report always says which scanners ran, so you know what an empty result
covers.

A scanner hit is a candidate like any other and goes through the refutation
pass: most scanner output is hardening advice, not an exploit.

Two scanners use the network:

- `semgrep` downloads its rules from the Semgrep registry. Without network
  access it cannot get them, and the skill goes on without it;
- `trufflehog` without `--no-verification` sends each key it finds to the
  provider to test it. The skill asks you before it turns verification on.

## Each finding carries

- the file and line;
- the CWE and the OWASP Top 10:2025 category;
- the exploit scenario: who the attacker is, what input they send, what
  happens;
- the refutation score;
- the fix, with code;
- the variants: the same pattern found elsewhere in the repository, refuted
  the same way.

At the end the skill gives a posture score from 1 to 10, computed by fixed
rules: the same findings always give the same score.

## Install

```bash
git clone https://github.com/vadbosh/security-sieve.git
cd security-sieve
./install.sh --dry-run   # what would be written
./install.sh
```

The installer copies `skills/security-sieve/` into each assistant it finds:
`~/.claude/skills`, `~/.config/opencode/skills`, `~/.codex/skills`. It writes
nothing else. Re-running it replaces only the files that changed.

To install into another directory:

```bash
./install.sh --skills-dir <path>
```

In the assistant:

```
/security-sieve                  # the current branch against its merge base
/security-sieve src/api/         # a directory
/security-sieve threat model of the upload service
```

Asking for a "security review" in plain words also triggers the skill.

### Claude Code has its own `/security-review`

Claude Code ships a built-in `/security-review` command, which reviews the
branch diff. This skill has a different name, so the built-in command stays
available. The skill adds a refutation pass for every finding, a code mode,
the infrastructure and agent guides, and tool evidence.

## Where it comes from

The skill started as `security-review` from
[getsentry/skills](https://github.com/getsentry/skills). The reference
material in `references/`, `languages/python.md`, `languages/javascript.md`
and `infrastructure/docker.md` is copied from it unchanged. Sentry derived that
material from the [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/).

`UPSTREAM` pins the commit those copies came from and records their checksums.
`./release.sh check` fails if a copy changes, and `./release.sh upstream`
reports when Sentry moves.

The refutation pass and the exclusion rules follow
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review),
restated in our own words.

## License

Two licenses, file by file. `skills/security-sieve/LICENSE` says which file is
under which.

- **Apache License 2.0** (`LICENSE`) covers SKILL.md, every guide whose first
  line is an `SPDX-License-Identifier: Apache-2.0` comment, and the scripts.
- **CC BY-SA 4.0** covers the reference material copied from getsentry/skills.
  You may share and adapt it with credit, and an adaptation has to keep the
  same license.

`NOTICE` gives the attributions.

## Contributing

Every check runs locally:

```bash
./release.sh check
```

It compares the version, changelog, tag, guide index, licenses, upstream
copies and installed copies, and looks for paths of your machine in the shipped
files.

A new guide starts with `<!-- SPDX-License-Identifier: Apache-2.0 -->` and is
written in your own words. OWASP and Trail of Bits text is CC BY-SA 4.0: link to
it, do not copy it. A guide is shipped only when an index table in SKILL.md
names it.
