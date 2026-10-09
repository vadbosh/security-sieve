# security-sieve: how it works

[Русская версия](guide.ru.md) · [README](../README.md)

## Why two passes

Reviewers, human and model alike, tend to see bugs and to overrate them. Say a
report has three real findings among twenty plausible ones. The reader cannot
tell which three are real, so the report is worth less than one with the three
alone. The skill therefore separates finding from judging:

1. **Hunt.** Collect candidates. Each one names a location, the input, the sink
   and what an attacker gains.
2. **Refutation.** Check each candidate again, on its own, in a fresh context,
   with the goal of breaking it.

## Modes

| You ask | Mode | What happens |
|---|---|---|
| "review my changes", or no target inside a git repository | Diff | Reads the branch against its merge base (`origin/HEAD`, `main`, `master`, `trunk`, `develop`), plus uncommitted and untracked files. Reports what the change introduces or makes reachable. Older issues go under "Outside the diff" and do not count toward the score. No base found: the skill asks instead of reviewing an empty range |
| a file, a directory, a repository | Code | Starts from the entry points (routes, handlers, CLI arguments, consumers) and follows the data to the sinks |
| a threat model, "is this CVE exploitable" | Threat model | STRIDE, attack surface, CVE and dependency triage |
| IAM, Kubernetes, Terraform, CI pipelines | Infrastructure | The guide for that kind of configuration |

## The refutation pass

Where the assistant can start subagents, each candidate gets its own, at most
five at a time. A subagent sees only what it is given, so it gets, in full
text:

- the candidate;
- the refutation step;
- the whole "Do not flag" section of `SKILL.md`;
- the guides loaded for that code;
- what to return: a one-sentence claim, an exploit scenario, a score, the
  exclusion that applies.

It does not see the other candidates. Without subagents the skill takes the
candidates one at a time and re-reads the code for each.

| Score | Outcome |
|---|---|
| 8–10 | Finding, reported with severity |
| 5–7 | "Needs verification", with the question that would settle it |
| 1–4 | Dropped, not mentioned |

A confirmed finding is then searched for across the repository; each variant
goes through the same refutation.

## What it does not report

These classes are excluded outright, whatever their severity would be:

- denial of service, resource exhaustion, missing rate limits, regex DoS — in
  every mode; a threat model may list availability threats as design notes;
- missing hardening with no exploit: an absent header or flag, unencrypted
  storage, a missing lock file, until an attacker has a path to the data;
- outdated libraries, unless the vulnerable call is shown to be reachable;
- theoretical race conditions and timing attacks;
- memory-safety issues in memory-safe languages;
- log spoofing, a missing audit log;
- SSRF that controls only the path;
- regex injection;
- user text inside an AI prompt, unless the model can then reach a tool with
  real side effects;
- secrets on disk that are otherwise protected;
- unpinned third-party code, unless its owner is outside your organisation
  **and** the job that runs it holds secrets or deploy rights (then Medium).

Environment variables and CLI flags count as trusted, except values built from
attacker-controlled event data, such as a CI variable set from a pull request
title.

A secret in git history **is** reported, even when HEAD no longer has it:
every clone still holds the commit. The fix is to rotate it first.

## How the scanners run

The skill runs installed scanners only, and treats every hit as a candidate.
Most scanner output is hardening advice, not an exploit.

- Output goes to a temporary directory outside the repository.
- The skill reads a projection: rule, file, line, commit. `gitleaks` runs with
  `--redact`; `trufflehog`, which prints the secret in its `Raw` field, is read
  through `jq`, and skipped when `jq` is missing. Secret values never reach the
  model, and the skill needs no redaction tool on the host.
- Secret scanners run twice: on git history (`git` mode) and on the working
  tree (`filesystem` / `dir` mode). The git modes do not see untracked or
  staged files. In a directory that is not a repository only the working-tree
  runs make sense: `gitleaks git` there reports "no leaks found" after
  scanning 0 commits.
- `checkov` runs with `-o cli --compact`; its JSON was about seven times larger
  for the same findings.
- `trivy` runs without its secret scanner, whose output carries the values.
- `semgrep` and `trivy` quote the matched source lines in their JSON; the skill
  reads both through a `jq` filter that drops those quotes, and skips them
  without `jq`.

Network use:

- `semgrep` downloads its rules from the Semgrep registry; without network
  access the skill goes on without it;
- `trufflehog` runs with `--no-verification`. Verification would send every
  key it finds to the provider, so the skill asks before turning it on.

The scanner commands are bash. Windows without Git for Windows has no bash:
Claude Code uses PowerShell there. The review is then basic: the model reads
the code and no scanner runs. The report says "Basic review: no scanners (no
bash shell)".

## The report

Each finding has the file and line, the CWE, the OWASP Top 10:2025 category,
an exploit scenario, the refutation score, the fix with code, and its
variants. The summary lists the tools that ran, and says whether git history
and uncommitted files were scanned for secrets.

The posture score is a formula, so the same findings always give the same
score:

1. Any Critical finding: `1` if there are two or more, or one is a live
   production secret; otherwise `2`.
2. Otherwise `10 − 4 × High − 1.5 × Medium − 0.5 × Low`, rounded down, never
   below `3`.

Needs-verification items and findings outside the diff do not count.

## Install details

- The installers write only into assistants that are already present:
  `~/.claude/skills`, `~/.config/opencode/skills`, `~/.codex/skills` (the same
  paths under your profile on Windows). `--skills-dir <path>` /
  `-SkillsDir <path>` installs elsewhere; an empty value is refused.
- Re-running replaces only changed files. A file you edited by hand is copied
  to `~/.local/state/security-sieve-backups` (`%LOCALAPPDATA%` on Windows)
  first; the three newest copies are kept.
- A file left in an assistant's copy that the source no longer ships is
  reported, not deleted.
- Codex also reads `~/.agents/skills`, and its source marks `~/.codex/skills`
  as the older location kept for compatibility. The installer uses
  `~/.codex/skills`, like the author's other skill repositories; for the new
  location run `./install.sh --skills-dir ~/.agents/skills`.
- Both installers warn, in a coloured box, when `trufflehog`, `gitleaks` or
  `jq` is missing. On Windows without bash, `install.ps1`
  prints a "BASIC REVIEW" notice.

Claude Code ships a built-in `/security-review` command that reviews the
branch diff. This skill has another name, so the built-in command stays
available.

## License and provenance

The skill started as `security-review` from
[getsentry/skills](https://github.com/getsentry/skills) (Apache-2.0). Its
reference material is copied unchanged: 17 files in `references/`,
`languages/python.md`, `languages/javascript.md`, `infrastructure/docker.md`.
Sentry derived that material from the
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/), so it stays
under CC BY-SA 4.0. You may share
and adapt those files with credit; an adaptation keeps the same license.

Everything else is Apache-2.0: `SKILL.md` (derived from Sentry's, with
changes) and every guide whose first line is
`<!-- SPDX-License-Identifier: Apache-2.0 -->`. The refutation pass and the
exclusions follow
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review),
restated in our own words. `skills/security-sieve/LICENSE` says which file is
under which license; `NOTICE` gives the attributions.

`UPSTREAM` pins the commit the copies came from and their checksums.
`./release.sh verify` fails if a copy changes; `./release.sh upstream` reports
when Sentry moves.

## Contributing

```bash
./release.sh verify   # changelog section, index, licenses, upstream copies, machine paths
./release.sh check    # verify + tag, HEAD and installed copies, after a release is tagged
```

A new guide starts with `<!-- SPDX-License-Identifier: Apache-2.0 -->` and is
written in your own words: OWASP and Trail of Bits text is CC BY-SA 4.0, so
link to it instead of copying. A guide ships only when an index table in
`SKILL.md` names it.
