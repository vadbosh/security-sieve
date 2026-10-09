<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cloud Security Reference: IAM, Secrets Managers, Service TLS, Network Exposure

## Overview

This guide helps a reviewer decide whether a cloud permission, a secrets-manager
setup, a service-to-service TLS client or a network exposure gives an attacker
something. It is provider-neutral, with AWS first because the examples need a
concrete policy language. The rule behind every item is the one in `SKILL.md`: a
finding names who the attacker is, what they can reach and what they gain. A
setting that merely differs from a best-practice list is not a finding.

Do not repeat other guides, read them instead:

- Terraform HCL (IAM in `jsonencode`, trust policies, OIDC `sub`, S3, security
  groups, KMS key policies, EKS endpoint, state): `infrastructure/terraform.md`
- Kubernetes RBAC, pod credentials (IRSA, Pod Identity, IMDS hop limit), Secrets,
  Ingress: `infrastructure/kubernetes.md`
- Image content: `infrastructure/docker.md`. Pipeline trust: `infrastructure/ci-cd.md`
- Secrets committed to code or history, and log leaks: `references/data-protection.md`
  and the "Secrets in code" part of `SKILL.md`
- SSRF to the metadata service: `references/ssrf.md`
- Dependency and image CVEs: `references/threat-modeling.md` (step 5, dependency
  vulnerabilities) and `references/supply-chain.md`

| Class | CWE | OWASP Top 10:2025 |
|-------|-----|-------------------|
| Over-broad identity policy (wildcards on write or secret-read, `NotAction` with `Allow`) | CWE-269, CWE-732 | A01 Broken Access Control |
| Resource policy open to any principal (secret, queue, topic, registry) | CWE-284 | A01 Broken Access Control |
| Role chain that lets a low-trust identity reach a high-trust one | CWE-269 | A01 Broken Access Control |
| Vault or secrets-manager policy that grants a whole tree | CWE-732 | A01 Broken Access Control |
| TLS client that skips certificate or host verification | CWE-295, CWE-297 | A07 Authentication Failures |
| Service that relies on mTLS but does not verify client certificates | CWE-287, CWE-295 | A07 Authentication Failures |
| Internal or admin service reachable from the internet without authentication | CWE-306, CWE-668 | A02 Security Misconfiguration |

---

## Do not flag

Read this first. These are not findings, whatever a scanner says.

| Pattern | Why it is not a finding |
|---------|-------------------------|
| Wildcard `Resource` on read-only list or describe actions (`ec2:Describe*`, `s3:ListAllMyBuckets`, `iam:List*`) | Metadata only. Wildcard on write, delete, `iam:*`, `sts:AssumeRole` or `*:Decrypt`/`secretsmanager:GetSecretValue` is different. |
| A secret without rotation, or with a long rotation period | Missing hardening on its own (`SKILL.md` exclusion 2). It raises impact only after a confirmed way to read the secret. |
| A secret passed to a process as an environment variable | Environment variables are trusted (`SKILL.md` precedent). The question is who can read the secret store, not how the process receives the value. |
| Certificate lifetime, key size choice, revocation method (OCSP, CRL) | Design choice. Report a certificate only when its private key is exposed. |
| No mTLS between services inside a cluster or VPC, when no attacker path to the network is shown | Missing hardening. It matters once a finding gives an attacker a position on that network. |
| No private endpoints, no egress filtering, no WAF, no GuardDuty-style detection | Hardening and detection. Not exploit paths. |
| Compliance mapping (SOC 2, ISO 27001, PCI DSS, HIPAA), retention periods, asset inventory | Process, not vulnerability. |
| CVE patch SLA, a failed build on a CVE, a missing dependency scan | Exclusion 3. A CVE is reported only with a reachable vulnerable function. |
| `Deny` statements with wildcards | They restrict. |
| `Principal "*"` guarded by `aws:PrincipalOrgID`, `aws:SourceVpce`, `aws:SourceVpc` or `aws:SourceArn` in `Condition` | Restricted, not public (the same reading as in `terraform.md`). Check the condition value is not itself a wildcard. |
| `verify=False`, `InsecureSkipVerify` in tests, fixtures, local tooling or a flag that only an operator sets | Not attacker-controlled. Report it only on a production path where the code hardcodes it. |
| Role trusting the same account's own `:root` (`111122223333` here) | The AWS default. |
| Placeholders and documentation sample keys | Not credentials. |

---

## IAM policies and role chains

Applies to policy JSON wherever it lives: console exports, CloudFormation,
CDK output, CLI scripts, Terraform. HCL-specific forms and the
`PassRole`/`CreatePolicyVersion` escalation family are in `terraform.md`.

First ask who holds the policy. Read the trust policy of a role, or the users and
groups it is attached to. A wildcard on a role that nothing can assume is not
reachable. A wildcard on a role that a CI job, a public-facing workload or an
external account can assume is.

What the attacker gains: anything the policy allows, as the identity that holds
it. For a low-trust holder the finding is the difference between what the holder
needs and what the policy gives.

```json
// VULNERABLE: a web workload role can read every secret and write to every bucket
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "s3:PutObject"], "Resource": "*" }
  ]
}

// SAFE: named secret, one prefix
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
      "Resource": "arn:aws:secretsmanager:us-east-1:111122223333:secret:app/web/db-*" },
    { "Effect": "Allow", "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::example-uploads/web/*" }
  ]
}
```

### `NotAction` with `Allow`

`NotAction` matches everything except the listed actions. With `Effect: Allow`,
it grants everything not listed, including services the author never thought of.
AWS's own guide warns that this "could result in granting users more permissions
than you intended".

```json
// VULNERABLE (CWE-269): "everything except deleting a bucket", on any resource
{ "Effect": "Allow", "NotAction": "s3:DeleteBucket", "Resource": "*" }

// ALSO VULNERABLE: "everything except IAM" still allows reading every secret,
// decrypting with every key and starting compute with any role the holder can pass
{ "Effect": "Allow", "NotAction": "iam:*", "Resource": "*" }

// NORMAL: NotAction with Deny, used as a guardrail (restricts)
{ "Effect": "Deny", "NotAction": "iam:*", "Resource": "*",
  "Condition": { "BoolIfExists": { "aws:MultiFactorAuthPresent": "false" } } }
```

Report `Allow` plus `NotAction` on `Resource "*"` when a non-admin identity holds
it. Severity follows the holder, as for wildcards: High on an assumable workload
or CI role, nothing on a break-glass administrator role that is meant to be
all-powerful.

### Role chains

Trace the path `CI or workload -> role A -> role B`. Each hop is only as strong
as its trust policy.

- A role that trusts a whole other account (`:root`) with no `ExternalId` or
  condition lets any principal of that account, not only the intended one,
  assume it. For a third-party vendor the confused deputy applies; for a sibling
  account in the same organisation it needs verification.
- A chain where a low-trust role may assume a high-trust role (`sts:AssumeRole`
  on a production admin role) is privilege escalation. Report it with the path
  written out: who starts, which two policies allow each hop, what the end role
  can do.
- Long-lived access keys for a human or a service that could use a role: report
  only a key that is committed (see `SKILL.md`, "Secrets in code") or held by an
  identity with dangerous permissions and no other control. The mere existence
  of a key is hardening.

---

## Secrets managers and Vault

The attack is always the same: someone who should not read the secret can. So
review **who can read** (identity policy, resource policy, Vault policy, auth
method mapping) and **what the secret opens**. How a secret is stored,
rotated or delivered is context. Secrets written into code, images or history
are `data-protection.md` and `SKILL.md`.

### Resource policy open to any principal

Secrets Manager (and similar stores) accept a resource policy next to the
identity policies. A resource policy that allows `Principal "*"` (or a whole
foreign account) to read lets those principals fetch the value from outside the
account, whatever the identity policies say.

```json
// VULNERABLE (CWE-284): any AWS principal can read the secret
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "*"
  }]
}

// SAFE: only principals of the organisation
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": "*",
    "Action": "secretsmanager:GetSecretValue",
    "Resource": "*",
    "Condition": { "StringEquals": { "aws:PrincipalOrgID": "o-exampleorgid" } }
  }]
}
```

In Terraform the policy is an `aws_secretsmanager_secret_policy`. The provider
documents an optional `block_public_policy` argument that validates the policy
(with the Zelkova engine) and rejects broad public access. Its absence is not a
finding; a wide policy is.

Same shape, other stores: an SQS queue, SNS topic, ECR repository or KMS key with
`Principal "*"` and no `Condition`. On queues and topics, a `Send` or `Publish`
action open to everyone lets an outsider inject messages that consumers trust;
`Receive` or `Subscribe` open to everyone leaks the content. Read the action
before the principal.

Severity: High when the secret opens production data or credentials; Critical
when the secret is itself a live key to something external. Needs verification
when only the foreign account is named and it may be a sibling.

### Vault policy that grants a tree

A Vault policy is a list of `path` rules; unmatched paths are denied by default.
A glob `*` is a prefix match and is only supported as the last character of the
path. So `path "*"` is every path in the server.

```hcl
# VULNERABLE: every path, including sys/ (CWE-732)
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# ALSO VULNERABLE: a whole secrets mount for one service
path "secret/*" {
  capabilities = ["read", "list"]
}

# SAFE: one service reads its own subtree
path "secret/data/payments/api/*" {
  capabilities = ["read"]
}
```

What matters:

- `sudo` allows root-protected paths (Vault's docs give audit-backend changes as
  an example). With `path "*"` it is the whole server.
- Vault's own configuration lives under `sys/`, so a broad grant there is
  administration, not data access.
- `deny` wins over any other capability; a broad rule with explicit `deny`
  carve-outs for sensitive paths is not a finding on its own.
- Ask what the token holder is: an operator group or break-glass policy may
  legitimately hold `path "*"`. A policy mapped to an application's auth role,
  a CI identity or a broadly assigned group is the finding.
- Capabilities follow HTTP verbs, not the action: generating dynamic database
  credentials is a `GET`, so the dangerous grant is `read` on the credentials
  path. Check the path, not the capability name.

### Auth method that hands out the role

A Vault or cloud auth role that any caller can log in to (a Kubernetes or JWT
auth role with no bound service account, namespace, project or subject, an AWS
IAM auth role bound to `*`) is the same problem as an OIDC trust without a
`sub` condition: the attacker does not need to break anything, only to log in.
Read the bound claims before the policy.

---

## Service-to-service TLS

mTLS and plain TLS between services decide whether a network attacker (on the
path, or sharing the network) can read or change traffic and impersonate a peer.
Report a defect in **how verification is done**. Certificate lifetimes, CA
choice and rotation automation are design (see the end).

### Client that skips verification

```go
// VULNERABLE (CWE-295): any certificate is accepted for any host name
client := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}}

// SAFE: verify against the internal CA
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caPEM)
client := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
}}
```

```python
# VULNERABLE (CWE-295): accepts any certificate and ignores host name mismatch
requests.get("https://payments.internal/charge", verify=False)

# SAFE: default verification, or the internal CA bundle
requests.get("https://payments.internal/charge", verify="/etc/ssl/internal-ca.pem")
```

In Go, `InsecureSkipVerify: true` makes the client accept any certificate and any
host name. The `requests` documentation says the same of `verify=False`, and adds
that it makes the application vulnerable to man-in-the-middle attacks. Other
spellings with the same effect: `curl -k` and the equivalent switch of any other
HTTP or TLS library, or a custom verifier that always returns success.

Report only when all hold:

1. the call is on a production path (not a test, a migration helper or a local
   tool the user runs themselves);
2. the traffic carries something worth taking (credentials, tokens, user data,
   or a response the client acts on), or the response decides an authorisation;
3. a position between the two ends is plausible: the traffic leaves the host
   (another node, another network, the internet, a shared network segment).
   Loopback to a sidecar in the same pod is not.

Severity: High for credentials or tokens sent over the unverified link across a
network; Medium when the link is inside one small trusted network. When the skip
is behind a configuration switch only operators set, the code is not
attacker-controlled: do not flag, unless the shipped default is "skip".

### Server that says "mTLS" but does not verify the client

mTLS authenticates the caller by its certificate. If the server asks for a client
certificate and then does not verify it against the CA, or accepts connections
without one, the "mTLS" protects nothing and the endpoint is open to anyone on the
network who can reach it.

Report when the service's own authorization depends on the peer identity
(an allow-list of caller names, or "only internal callers") and verification is
off, optional or lets plaintext through. In server code, read the client-certificate
mode of the TLS configuration: one that requests but does not verify (or does not
require) a client certificate is this finding. In a service mesh, read the
policy that sets whether plaintext is accepted next to mTLS. A migration-period
setting that accepts both is a note, not a finding, unless the identity
allow-list is the only control. Look up the exact setting names in the docs of
the library or mesh version in use before quoting them.

Hostname verification must also be on: a certificate valid for any host of the
internal CA, accepted for every host, lets one compromised service impersonate
another (CWE-297).

---

## Network exposure beyond security groups

Security groups, public database flags, public S3 and the EKS endpoint are in
`terraform.md`. This part is the logic that does not depend on the tool.

A service is exposed when **both** are true: an attacker can route to it, and it
asks for nothing, or something the attacker has or can guess. Establish the
first from the chain: public address, load balancer scheme, security group or
firewall source, route table, resource policy `Principal`. Establish the second
from the application: is there authentication, and does it have a default
credential?

| Exposed | Gain | Usually |
|---------|------|---------|
| Admin or debug interface (dashboard, metrics UI, queue console, database admin) on a public address without authentication | Read configuration and data, often run commands | High to Critical |
| Message queue or topic accepting writes from any principal | Inject work that consumers trust | High when consumers act on content |
| Internal API trusted because of its network position, reachable from a public workload that an attacker controls through another bug | Lateral movement | Needs verification: requires the other bug |
| Cloud metadata endpoint reachable from code that fetches attacker-chosen URLs | Role credentials | Report in the SSRF finding, see `ssrf.md` |

Zero trust, private endpoints and egress filtering are good design. Their
absence is not a finding without a path (see "Do not flag").

---

## Design reference — not findings

Items below describe a sound design. Use them to word a recommendation inside a
real finding. Do not report their absence.

- Service certificates from a private CA with automated issuance and short
  lifetimes; lifetime is a trade-off between the exposure window and the load on
  the issuing system.
- Secrets in one managed store with per-service access, an audit trail of reads,
  and dynamic short-lived credentials where the store supports them.
- Identity for CI through federation instead of stored keys.
- Patch timelines and compliance frameworks are organisational policy.
- Scanners (Checkov, Trivy, KICS) help find candidates: invocations are in
  `SKILL.md` step 3 and `terraform.md`. tfsec's own README says its scanning has
  moved into Trivy, so use Trivy.

---

## Grep patterns

```bash
rg -n '"NotAction"|NotAction\s*=|"Principal"\s*:\s*"\*"|Principal.*"\*"' --glob '*.{json,tf,yaml,yml}'
rg -n 'secretsmanager:GetSecretValue|kms:Decrypt|sts:AssumeRole' --glob '*.{json,tf,yaml,yml}'
rg -n 'path\s+"\*"|capabilities.*sudo' --glob '*.{hcl,json,tf}'
rg -n 'InsecureSkipVerify|verify\s*=\s*False|curl.* -k ' --glob '!*test*'
```

A match is a candidate. Run it through the exclusions above and the refutation
pass in `SKILL.md`.

---

## Testing checklist

- [ ] Every wildcard, `NotAction` or open `Principal` has a named holder, and the holder's trust policy was read
- [ ] Secret and resource policies: principal, action and condition were read, not only the name
- [ ] Vault policies and auth roles: bound claims and mapped policies checked; no `path "*"` for a workload
- [ ] TLS clients that skip verification are on a production path with traffic worth taking
- [ ] Services that authenticate by peer certificate verify it
- [ ] Each finding states who the attacker is, what they reach and what they gain

## References

- [AWS IAM: NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html)
- [AWS: confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [Terraform AWS provider: `aws_secretsmanager_secret_policy`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_policy)
- [Vault: policies](https://developer.hashicorp.com/vault/docs/concepts/policies)
- [Go: crypto/tls](https://pkg.go.dev/crypto/tls)
- [Requests: SSL cert verification](https://requests.readthedocs.io/en/latest/user/advanced/)
- [tfsec to Trivy migration](https://github.com/aquasecurity/tfsec)
- [OWASP Top 10:2025](https://owasp.org/Top10/)
