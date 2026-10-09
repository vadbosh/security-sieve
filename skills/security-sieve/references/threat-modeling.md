<!-- SPDX-License-Identifier: Apache-2.0 -->
# Threat Modeling and CVE Triage Reference

STRIDE threat modeling, attack surface, CVE research, dependency triage and a
remediation plan. Merged in from the former `security-researcher` skill. Auth,
crypto and input validation are not repeated here: `authentication.md`,
`authorization.md`, `cryptography.md`, `injection.md`, `xss.md`, `ssrf.md`,
`file-security.md`.

## Process

1. **Scope** — map the architecture: components, dependencies, data flows,
   trust boundaries. Name the threat actors (opportunistic, targeted, insider)
   and the assets (credentials, business logic, data, availability).

2. **STRIDE** — apply to each component and each data flow:
   - **S**poofing — identity forgery at trust boundaries
   - **T**ampering — data modification in transit or at rest
   - **R**epudiation — missing audit trails (`logging.md`)
   - **I**nformation disclosure — data leakage paths (`data-protection.md`)
   - **D**enial of service — availability attack surfaces
   - **E**levation of privilege — authorization bypass paths (`authorization.md`)

3. **Attack surface** — catalog every entry point: network services and their
   auth, API endpoints and their input validation, file uploads,
   deserialization points, admin interfaces, third-party integrations that
   accept external data.

4. **CVE research** — NVD, MITRE CVE, vendor advisories, Exploit-DB, GitHub
   Security Advisories for the stack. Map each CVE to the deployed component
   version and assess exploitability in this environment.

5. **Dependency vulnerabilities (SBOM)** — scan against vulnerability
   databases (tools: `supply-chain.md`), then triage:
   - Exploitability: is the vulnerable code path reachable?
   - Severity: CVSS 3.1 base score adjusted with environmental metrics
   - Remediation: patch available / version upgrade / no fix

6. **Remediation plan** — prioritize by `risk = likelihood × impact`. Group
   into themes (input validation, dependency updates, config hardening). Give
   a specific fix with a code example for each.

## Standards

- A CVE counts only when its vulnerable code path is reachable here.
- CVSS 3.1 with environmental metrics: the base score alone over- or understates risk.
- A threat model is updated when the architecture changes; a stale one gives false confidence.
- A remediation is specific: "use parameterized queries" plus the example, not "fix SQL injection".

## Verification

- The threat model covers every component and data flow of the current architecture.
- CVE findings match the component versions actually deployed.
- A remediation is verified in a test environment: the issue is no longer exploitable.
- A sample of dependency-scan results matches a manual CVE lookup.
- Critical findings rank above medium ones on both likelihood and impact.
