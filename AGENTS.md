# security-sieve

A security-review skill for Claude Code, Codex and Opencode. Its one rule:
report only what survives a refutation pass.

## Commands

```bash
./install.sh --dry-run    # what would be written into the assistant directories
./release.sh check        # version, changelog, tag, index, licenses, upstream copies, installed copies
./release.sh upstream     # has getsentry/skills moved since the pin (network)
```

## A task is done when

- `./release.sh check` passes and its output is in the reply;
- a change to the method in SKILL.md was tried on a real target, not only read.

## Rules for this repository

- Files listed in `UPSTREAM` are CC BY-SA 4.0 copies. Do not edit them in
  place. To change one, copy it to a new file of our own or record the change
  in `NOTICE` and update its checksum in `UPSTREAM`.
- Every new guide starts with `<!-- SPDX-License-Identifier: Apache-2.0 -->`
  and is written in our own words: OWASP and Trail of Bits text is
  CC BY-SA 4.0 — link to it, do not copy it.
- A guide is shipped only when SKILL.md names it in an index table.
- Commit messages are in English and explain why.
