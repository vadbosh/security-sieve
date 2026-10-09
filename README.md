# security-sieve

A security-review skill for Claude Code, Codex and Opencode that **reports only
vulnerabilities an attacker can exploit**.

It works in two passes. First it collects candidates. Then it checks each
candidate again, on its own, trying to prove it is not a vulnerability. Only a
candidate that survives, scored 8 of 10 or higher, goes into the report.

[Русская версия](README.RU.md) · [How it works](docs/guide.en.md)

## Install

Linux, macOS:

```bash
git clone https://github.com/vadbosh/security-sieve.git
cd security-sieve
./install.sh
```

Windows:

```powershell
.\install.ps1
```

The installer copies the skill into every assistant it finds: `~/.claude`,
`~/.config/opencode`, `~/.codex`. `--dry-run` / `-DryRun` shows what it would
write.

Run it in the assistant:

```
/security-sieve                  # the current branch against its merge base
/security-sieve src/api/         # a directory
/security-sieve threat model of the upload service
```

## Dependencies

Only the assistant is required. Everything else adds coverage. The skill runs
what is installed, installs nothing, and the report says what ran.

> [!IMPORTANT]
> **Install `trufflehog` and `gitleaks`.** Only they let the review see git
> history: a key deleted three commits ago is still in every clone. Without
> them the report says "Secrets in git history: NOT scanned".
>
> ```bash
> brew install trufflehog gitleaks
> ```
>
> Other systems: [trufflehog](https://github.com/trufflesecurity/trufflehog/releases),
> [gitleaks](https://github.com/gitleaks/gitleaks/releases).

| Tool | Required | Adds | Without it |
|---|---|---|---|
| Claude Code, Codex or Opencode | yes | runs the skill | — |
| `git` | for diff mode | the merge base, the branch diff, untracked files | No diff mode; files and directories are still reviewed |
| `bash` | for scanners | runs the scanner commands. On Windows: Git Bash | **Basic review**: the model reads the code, no scanner runs. The installer and the report say so |
| `jq` | for `trufflehog` | reads `trufflehog` output without the secret values | `trufflehog` is skipped; `gitleaks` still runs |
| [`trufflehog`](https://github.com/trufflesecurity/trufflehog) | strongly recommended | secrets in every commit and in files not committed yet | A secret is found only if it is in a file the model reads |
| [`gitleaks`](https://github.com/gitleaks/gitleaks) | strongly recommended | the same, with other rules; values masked by `--redact` | Same as above. One of the two already covers git history |
| [`semgrep`](https://semgrep.dev/docs/getting-started/) | optional | code patterns in many languages. Downloads its rules from the Semgrep registry | The model follows the code from the entry points; on a large tree it may miss a far sink |
| [`osv-scanner`](https://google.github.io/osv-scanner/) | optional | known-vulnerable dependency versions from lockfiles | No dependency CVE list in threat-model mode. Code mode reports a CVE only when the vulnerable call is reachable anyway |
| [`trivy`](https://trivy.dev/) | optional | dependencies and IaC misconfiguration | Partly covered by the others |
| [`checkov`](https://www.checkov.io/) | optional | policy checks for Terraform, Kubernetes, Dockerfiles, CI | Terraform and Kubernetes are reviewed from the guides alone |

Secret values never reach the model: the skill masks them itself and needs no
redaction tool on your machine.

## What it checks

| Area | What it looks for | Guide in `skills/security-sieve/` (`references/` unless named) |
|---|---|---|
| Injection | SQL, NoSQL, OS command, LDAP, template injection | `injection.md` |
| Web output | Reflected, stored and DOM XSS; CSRF | `xss.md`, `csrf.md` |
| Access | Authorization, IDOR, privilege escalation; sessions, password storage | `authorization.md`, `authentication.md` |
| Data | Weak crypto and randomness, secrets exposure, PII, deserialisation | `cryptography.md`, `data-protection.md`, `deserialization.md` |
| Files and requests | Path traversal, uploads, XXE; SSRF | `file-security.md`, `ssrf.md` |
| API and logic | Mass assignment, GraphQL, race conditions, workflow bypass | `api-security.md`, `business-logic.md` |
| Configuration | Headers, CORS, debug mode, fail-open error handling, logging | `misconfiguration.md`, `error-handling.md`, `logging.md` |
| Supply chain | Dependencies, build, unpinned third-party code | `supply-chain.md` |
| Secrets | Keys in code and in git history, including deleted ones | scanners + `SKILL.md` |
| AI agents | Tools with side effects, MCP servers and clients, skills, hooks, prompt injection | `agentic.md`, `modern-threats.md` |
| Python | Django, Flask, FastAPI | `languages/python.md` |
| JavaScript, TypeScript | Node, Express, React, Vue, Next.js | `languages/javascript.md` |
| PHP | Laravel, Symfony, plain PHP | `languages/php.md` |
| Containers | Dockerfile and runtime | `infrastructure/docker.md` |
| Kubernetes, Helm | Pod security, RBAC, secrets, ingress, charts | `infrastructure/kubernetes.md` |
| Terraform | IAM, network exposure, state and secrets in HCL | `infrastructure/terraform.md` |
| CI/CD | GitHub Actions, GitLab CI, Jenkins | `infrastructure/ci-cd.md` |
| Cloud | IAM policies, secrets managers and Vault, service TLS | `infrastructure/cloud.md` |
| Threat model | STRIDE, attack surface, CVE and dependency triage | `threat-modeling.md` |

Each finding has its file and line, CWE, OWASP Top 10:2025 category, exploit
scenario, refutation score, fix and variants. What the skill deliberately does
not report — denial of service, missing hardening, theoretical races — is in
[the guide](docs/guide.en.md#what-it-does-not-report).

## License

Apache-2.0 for the skill and our guides; the reference material from
[getsentry/skills](https://github.com/getsentry/skills) stays CC BY-SA 4.0.
Details: [docs/guide.en.md](docs/guide.en.md#license-and-provenance), `NOTICE`.
