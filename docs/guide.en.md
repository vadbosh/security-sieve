# security-sieve: how it works

[Русская версия](guide.ru.md) · [README](../README.md)

## Why two passes

Reviewers, human and model alike, tend to see bugs and to overrate them. Say a
report has three real findings among twenty plausible ones. The reader cannot
tell which three are real, so the report is worth less than one with the three
alone. The skill therefore separates finding from judging:

1. **Hunt.** Collect candidates. Each one names a location, the input, the sink
   and what an attacker gains. Where objects have owners — users,
   organisations, tenants — the hunt starts with an authorisation inventory:
   every entry point that takes an object id, and whether the code ties that
   id to the caller. An id with no tie is a candidate.
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

Where the assistant can start subagents, each candidate gets a subagent of its
own, at most five at a time. A subagent sees only what it is given, so it
gets, in full text:

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

For each confirmed finding the skill then searches the repository for the same
pattern; every match goes through the same refutation.

## What it does not report

The following classes are excluded outright, whatever their severity would be:

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
Most scanner output is hardening advice, not an exploit. The scanners are run
by `scripts/scan.sh`, not by the model command by command: the script finds
every installed tool, runs each one every time, and prints only grouped
results without secret values.

- The script opens with a short summary between two `━━━` bars: which
  scanners ran, which failed, which are missing. The skill pastes it into the
  chat as a `diff` block, so a scanner that ran shows green and one that
  failed or is missing shows red.
- Output goes to a temporary directory outside the repository, and the skill
  deletes it once the report is written.
- In Claude Code the scanners run in the background while the model reads the
  code. In Codex and Opencode they run one after another.
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
- `trivy` and `checkov` run without their secret scanners. `trivy` output
  would carry the values, and `checkov` only repeats what `trufflehog` and
  `gitleaks` find.
- `semgrep` and `trivy` quote the matched source lines in their JSON; the skill
  reads both through a `jq` filter that drops those quotes, and skips them
  without `jq`.

Network use:

- `semgrep` downloads its rules from the Semgrep registry; without network
  access the skill goes on without it;
- `trufflehog` runs with `--no-verification`. Verification would send every
  key it finds to the provider, so the skill asks before turning it on.
- `trufflehog` also runs with `--no-update`. Without it, it first tries to
  replace its own binary, and in a sandbox it then exits without scanning.
- A web search runs on the assistant provider's side, so a sandbox does not
  stop it. The skill lets the model search for public names only — a
  library, a version, an API, a CVE id — and never for code, paths, hosts or
  values from the repository.

The scanner commands are bash. Windows without Git for Windows has no bash:
Claude Code uses PowerShell there. The review is then basic: the model reads
the code and no scanner runs. The report says "Basic review: no scanners (no
bash shell)".

## The report

Before the review starts, the skill names the model it runs on and asks in one
dialog where the report goes, in which format and in which language. Where the
assistant has no question tool — Codex in its default mode — the questions come
as a numbered list, and you answer with three digits:

| Question | Options | Default |
|---|---|---|
| Where | `~/security-reviews/<repo>-<date>.<ext>`; a path you name; chat only | `~/security-reviews/…` |
| Format | `md`; `txt` (plain text, 80 columns); `html` (one file, inline styles, no scripts or external resources) | `md` |
| Language | the language of the session; English | the language of the session |

Inside the reviewed repository only if you choose it: a report lists every
weakness, and in a checkout it is one `git add -A` away from a commit. A
subagent or a run nobody can answer uses the defaults and says so in the
report. An existing report is never overwritten: when the name is taken, the
skill picks one that tells the reports apart — by scope, time or number. Paths,
code, CWE and OWASP identifiers stay untranslated, and no format ever contains
a secret value.

Right after your answer the skill checks that it can write to the chosen
directory. Codex in `workspace-write` mode writes only to its working
directory, `/tmp` and the directories listed in `writable_roots`, so
`~/security-reviews` is often closed to it. The skill then says so before
the review starts and offers `/tmp/security-reviews/` or a path you name. To
let Codex write to the default directory, add it to `~/.codex/config.toml`:

```toml
[sandbox_workspace_write]
writable_roots = ["/home/you/security-reviews"]
```

Every report opens with a notice under its title. The report is the model's
assessment, not a final verdict. A person checks each finding against the
code and the deployment before acting on it. What the report does not mention
was not proven safe. The notice is in every format and language, because a
report is forwarded without this guide.

Each finding has the file and line, the CWE, the OWASP Top 10:2025 category,
an exploit scenario, the refutation score, the fix with code, and its
variants — the same pattern elsewhere in the repository. The summary names
the model that ran the review, lists the tools that ran, and says whether git
history and uncommitted files were scanned for secrets.

The posture score is a formula, so the same findings always give the same
score:

1. Any Critical finding: `1` if there are two or more, or one is a live
   production secret; otherwise `2`.
2. Otherwise `10 − 4 × High − 1.5 × Medium − 0.5 × Low`, rounded down, never
   below `3`.

Needs-verification items and findings outside the diff do not count.

## Install details

- The installers write only into the skills directories of assistants that are
  already installed:
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
reference material is copied from it: 17 files in `references/`,
`languages/python.md`, `languages/javascript.md`, `infrastructure/docker.md`.
One line differs: a grep pattern in `references/injection.md` that GNU grep
rejected, fixed and recorded in `NOTICE`. Sentry derived that material from the
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
whether Sentry has new commits.

## Contributing

```bash
./release.sh verify   # changelog section, index, licenses, upstream copies, machine paths
./release.sh check    # verify + tag, HEAD and installed copies, after a release is tagged
```

A new guide starts with `<!-- SPDX-License-Identifier: Apache-2.0 -->` and is
written in your own words: OWASP and Trail of Bits text is CC BY-SA 4.0, so
link to it instead of copying. A guide ships only when an index table in
`SKILL.md` names it.
