<!-- SPDX-License-Identifier: Apache-2.0 -->
# Terraform Security Reference

## Overview

Terraform (and OpenTofu, which reads the same HCL) turns text into cloud
resources. A review asks two things: what will an outsider be able to do once
this is applied, and what does the repository leak or execute today. AWS names
are used below; the logic carries to other providers.

IAM principles, secrets stores and mTLS design are in `infrastructure/cloud.md`.
This file covers only what is visible in HCL. CI pipeline issues:
`references/supply-chain.md`.

Report only when the HCL shows a path an unauthenticated or wrongly trusted party
can use. See "Tool Evidence" and "Do Not Flag" at the end.

| Class | CWE | OWASP Top 10:2025 |
|-------|-----|-------------------|
| Over-broad IAM permissions, PassRole | CWE-269 | A01 Broken Access Control |
| Public S3, public data stores, public EKS API | CWE-284 | A01 Broken Access Control |
| Open admin or database ports | CWE-284 | A02 Security Misconfiguration |
| Weak trust policy, OIDC without `sub` | CWE-287 | A07 Authentication Failures |
| Secrets in code, outputs, state | CWE-798, CWE-312 | A04 Cryptographic Failures |
| Unprotected state backend | CWE-922 | A02 Security Misconfiguration |
| `local-exec` / `external` injection | CWE-78 | A08 Software or Data Integrity Failures |
| Unpinned module or provider source | CWE-829 | A03 Software Supply Chain Failures |
| KMS key policy open to `*` | CWE-732 | A01 Broken Access Control |

---

## IAM Policies in HCL

Policies appear as `jsonencode({...})`, heredoc JSON, `data "aws_iam_policy_document"`,
`aws_iam_policy`, `aws_iam_role_policy` and `assume_role_policy`. Read `Effect`
first: `Deny` with wildcards is fine.

### Wildcards

```hcl
# VULNERABLE: all actions on all resources (CWE-269)
resource "aws_iam_role_policy" "app" {
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
# SAFE: Action = ["s3:GetObject"], Resource = "${aws_s3_bucket.data.arn}/reports/*"
```

Also reportable: `iam:*`, `sts:*`, or write/`kms:Decrypt` actions with `Resource = "*"`. Severity depends on who can assume the identity: High on a production or CI role, not reachable on a role nothing assumes (read the trust policy first).

### iam:PassRole on `*`

```hcl
# VULNERABLE: any role can be handed to a service the holder can start
Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
Resource = "*"

# SAFE: Resource = <one role ARN>, Condition iam:PassedToService = "lambda.amazonaws.com"
```

Report when PassRole and a way to create compute are in the same identity. PassRole
on `*` alone is Medium, needs verification. Same class: `iam:CreatePolicyVersion`,
`iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`.

### Trust policies

```hcl
# VULNERABLE: anyone can assume the role
Principal = { AWS = "*" }          # also: Principal = "*"

# VULNERABLE: a whole third-party account, no condition
Principal = { AWS = "arn:aws:iam::999988887777:root" }

# SAFE (third party): ExternalId prevents the confused deputy
Principal = { AWS = "arn:aws:iam::999988887777:root" }
Condition = { StringEquals = { "sts:ExternalId" = var.vendor_external_id } }
```

`Principal "*"` with no `Condition` on an assumable role is Critical. A
cross-account `:root` trust without conditions is High for an unknown third party,
needs verification for a sibling account in the same organisation. Trusting the
current account's own `:root` (`111122223333` in these examples) is the AWS
default.

### GitHub and GitLab OIDC without a subject condition

A role that trusts a CI provider's OIDC issuer is assumable by every workflow the
issuer signs for. GitHub's issuer is shared by all repositories on github.com: with
only an `aud` check, any GitHub user can assume the role. This is a known
real-world takeover pattern; AWS and GitHub both say to evaluate
`token.actions.githubusercontent.com:sub` in such a trust policy.

```hcl
# VULNERABLE: audience only. Any GitHub repository can assume this role.
data "aws_iam_policy_document" "gha_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}
# Also weak: values = ["repo:*"], or StringLike "repo:my-org/*" on a powerful role.

# SAFE: pin owner, repository and ref or environment
condition {
  test     = "StringEquals"
  variable = "token.actions.githubusercontent.com:sub"
  values   = ["repo:my-org/my-repo:ref:refs/heads/main"]
}
```

GitLab: the condition must match `<gitlab-host>:sub` (for example
`project_path:my-group/my-project:ref_type:branch:ref:main`), not only `:aud`.
Missing `sub` on a role with write permissions is High; read-only is Medium.

---

## S3

`aws_s3_bucket_public_access_block` takes `block_public_acls`,
`block_public_policy`, `ignore_public_acls`, `restrict_public_buckets`. The same
four exist on `aws_s3_account_public_access_block` and default to `false`.

```hcl
# VULNERABLE: blocks off and a public ACL (CWE-284)
resource "aws_s3_bucket_public_access_block" "b" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"          # or public-read-write, authenticated-read
}

# VULNERABLE: bucket policy with Principal "*" (type "*", identifiers ["*"]) and s3:GetObject / s3:*
# SAFE: all four blocks true, no Principal "*" policy
```

- `Principal "*"` plus read on a bucket holding data, backups, logs or state,
  with the blocks off: High to Critical.
- Same on a bucket that serves a public site or static assets (website
  configuration, CloudFront origin, name or tags say `public`, `static`): intended.
  A write action for `*` is a finding even there.
- `Principal "*"` with `aws:SourceVpce`, `aws:SourceVpc`, `aws:PrincipalOrgID` or
  `aws:SourceArn` in `Condition` is restricted, not public.

---

## Network and Public Data Stores

Rule shapes: inline `ingress {}` in `aws_security_group`, `aws_security_group_rule`,
`aws_vpc_security_group_ingress_rule` (`cidr_ipv4`, `cidr_ipv6`, `from_port`,
`to_port`, `ip_protocol`).

```hcl
# VULNERABLE: admin port open to the internet (CWE-284)
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.app.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

# SAFE: referenced_security_group_id = <bastion group>, or a known cidr_ipv4
```

Sensitive ports: 22, 3389, 3306, 5432, 6379, 9200/9300, 27017 (also 1433, 11211, 2375).

- Sensitive port from `0.0.0.0/0` or `::/0` on a group attached to a real
  instance or database: High. Critical when the service has no auth by default
  (Redis, Elasticsearch, MongoDB) and sits in a public subnet.
- 80/443 from `0.0.0.0/0` on an internet-facing ALB, NLB or CDN origin: intended.

### Publicly reachable databases

`publicly_accessible = true` is reachable only if the subnet routes to an
internet gateway and the group allows the source. Flag + open rule: High. Flag
alone: Medium, needs verification. Same check for `aws_rds_cluster_instance`,
`aws_redshift_cluster`, `aws_dms_replication_instance`. For `aws_opensearch_domain`
read `access_policies` (`Principal "*"` without `Condition`) and whether
`vpc_options` is absent. ElastiCache has no public flag: look at subnet and
security group (6379). Unencrypted storage (`storage_encrypted`, EBS `encrypted`)
is hardening: report only with clear sensitive-data context (Low).

---

## EKS

```hcl
# VULNERABLE: API server open to the internet (CWE-284)
resource "aws_eks_cluster" "main" {
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs    = ["0.0.0.0/0"]   # also the default when omitted
  }
}

# SAFE: endpoint_private_access = true, endpoint_public_access = false, or a narrow public_access_cidrs
```

A public endpoint is still behind IAM and RBAC; it is not code execution by
itself. High when combined with a weak access grant below or anonymous auth;
alone Medium, needs verification.

```hcl
# VULNERABLE: cluster-admin for a broad principal (CWE-269)
resource "aws_eks_access_policy_association" "all" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = "arn:aws:iam::111122223333:root"
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}
# Legacy aws-auth ConfigMap: mapRoles with groups ["system:masters"] for a role
# that CI, developers or nodes can assume.
# SAFE: AmazonEKSViewPolicy with access_scope { type = "namespace", namespaces = ["team-a"] }
```

---

## Secrets in Code, Outputs and State

### Hardcoded credentials (CWE-798)

```hcl
# VULNERABLE: static provider credentials
provider "aws" {
  access_key = "<literal key id>"
  secret_key = "<literal secret>"
}

# VULNERABLE: secret as variable default, or literal in a resource
variable "db_password" {
  type    = string
  default = "<literal password>"
}
# SAFE: no default, sensitive = true, or manage_master_user_password = true (RDS)
```

A real-looking live key or password in tracked files is Critical and must be
rotated. Placeholders (`changeme`, vendor documentation sample keys) and obvious
local-only defaults are not findings. A tracked `terraform.tfvars`,
`*.auto.tfvars` or `*.tfvars.json` with real secrets is a finding. Provider
credentials from the environment or OIDC are the intended pattern.

### SSM parameters and outputs

```hcl
# VULNERABLE: secret stored as plain String
resource "aws_ssm_parameter" "db" {
  name  = "/prod/db/password"
  type  = "String"
  value = var.db_password
}
# SAFE: type = "SecureString"
# VULNERABLE: secret shown in plan and apply output
output "db_password" {
  value = aws_db_instance.main.password
}
# SAFE: add sensitive = true
```

`SecureString` still leaves the plaintext in state (the provider docs say so), so state protection matters either way.

### State holds secrets

State is plaintext JSON with every attribute, including passwords and
`random_password` results. `sensitive = true` only hides values from CLI output.
The backend must be private, and `terraform.tfstate*` must never be committed.

```hcl
# VULNERABLE: state backend without encryption or locking
terraform {
  backend "s3" {
    bucket = "example-tfstate"
    key    = "prod/terraform.tfstate"
  }
}

# SAFE: encrypt = true, and locking via use_lockfile or dynamodb_table
```

- State bucket with no public-access block, or a policy readable by `*`: High.
  The bucket is often defined in another stack; follow the reference.
- `*.tfstate` or `*.tfstate.backup` tracked in git: High when it contains
  secret attributes. Check the content, not the file name.

`data "terraform_remote_state"` reads another stack's whole state, secrets included. Reportable only when a low-trust stack can read a high-trust one (network, IAM, prod).

---

## Command Injection: `local-exec` and `external` (CWE-78)

```hcl
# VULNERABLE: untrusted text interpolated into a shell command
resource "null_resource" "notify" {
  provisioner "local-exec" {
    command = "curl -d 'name=${var.customer_name}' https://hooks.example.com"
  }
}
data "external" "lookup" {
  program = ["bash", "-c", "./lookup.sh ${var.target}"]
}

# SAFE: pass data through the environment and quote it in the script
provisioner "local-exec" {
  command     = "./notify.sh"
  environment = { CUSTOMER_NAME = var.customer_name }
}
```

Trace the value before reporting:

- Operator-set `.tfvars`, pipeline variables only maintainers edit, constants,
  and outputs of trusted resources are server-controlled. Do not flag.
- Attacker-influenced sources: a branch name or merge request title passed as
  `TF_VAR_*`, a tag or SSM value writable by a lower-privileged party, a
  `data "http"` response from an external host, input from a self-service
  portal that generates Terraform.
- Metacharacters matter when `command` runs through a shell (the default).

---

## Supply Chain: Modules and Providers (CWE-829)

```hcl
# VULNERABLE: mutable reference. Whoever controls the branch controls your apply.
module "vpc" { source = "git::https://github.com/example-org/tf-vpc.git" }
module "iam" { source = "git::https://github.com/example-org/tf-iam.git?ref=main" }
module "eks" { source = "terraform-aws-modules/eks/aws" }   # no version: newest release

# SAFE: exact version, or a full commit SHA for git sources
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.24.0"
}
```

- Unpinned module from an unknown third party or personal account, in a stack
  that holds production credentials: Medium to High, verify who owns the source.
- Unpinned module from the organisation's own trusted repository: hardening,
  do not flag.
- Raw `http://` source, or a provider from an unexpected namespace that looks
  like a typosquat: check the namespace; a look-alike is High.
- Missing `.terraform.lock.hcl`: Low. Pipeline side: `references/supply-chain.md`.

---

## KMS Key Policies

```hcl
# VULNERABLE: any principal may use or administer the key (CWE-732)
resource "aws_kms_key" "data" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}
# NORMAL: the default `Principal = { AWS = "arn:aws:iam::111122223333:root" }` statement
```

`Principal "*"` without a `Condition` is High. With `kms:CallerAccount`,
`aws:PrincipalOrgID` or `kms:ViaService` it is restricted.

---

## Grep Patterns for Terraform

```bash
grep -rnE '"?Action"?[[:space:]]*[:=][[:space:]]*"\*"|iam:PassRole|Principal.*"\*"' --include=*.tf .
grep -rln 'token.actions.githubusercontent.com' --include=*.tf .      # then look for ":sub"
grep -rnE '(block_public_(acls|policy)|restrict_public_buckets)[[:space:]]*=[[:space:]]*false|public-read' --include=*.tf .
grep -rnE '0\.0\.0\.0/0|::/0|publicly_accessible[[:space:]]*=[[:space:]]*true' --include=*.tf .
grep -rnE 'endpoint_public_access|public_access_cidrs|system:masters|ClusterAdminPolicy' --include=*.tf .
grep -rnE '(access_key|secret_key|password|token)[[:space:]]*=[[:space:]]*"[^"$]+"' --include=*.tf --include=*.tfvars .
git ls-files | grep -E '\.tfvars$|\.tfstate'
grep -rnE 'local-exec|data "external"|source[[:space:]]*=[[:space:]]*"(git::|github\.com|https?://)"' --include=*.tf .
```

---

## Tool Evidence

Scanners find candidates fast; they do not decide exploitability. Run them
read-only on a checkout and write output outside the repository. Never run
`terraform apply`, and avoid `init`/`plan` against real state during a review.

```bash
# Checkov: HCL only, failed checks only, no code blocks, exit code 0
checkov -d . --framework terraform --quiet --compact --soft-fail

# Trivy config scanner (tfsec is folded into Trivy)
trivy config --severity HIGH,CRITICAL .        # (unverified)

# KICS
kics scan -p . -o /tmp/kics-out                # (unverified)
```

Checkov flags (`-d`, `-f`, `--framework`, `--quiet`, `--compact`, `--soft-fail`,
`--check`, `-o`) are in its CLI reference; the Trivy and KICS commands are not
confirmed against current docs.

Most hits are hardening. Candidates: open sensitive ports, `Principal "*"`,
wildcards on assumable roles, real secrets. Open the resource, follow variables,
read what is attached to it. A scanner check id is not evidence.

---

## Do Not Flag

- Missing encryption at rest, logging, versioning, tags or deletion protection.
  Hardening, not findings.
- `0.0.0.0/0` on 80 and 443 of an internet-facing load balancer or CDN origin.
- Egress `0.0.0.0/0` (the AWS default).
- Wildcard `Resource` on read-only list or describe actions. Wildcard on write,
  delete, `iam:*` or `kms:Decrypt` is different.
- `Deny` wildcards; public S3 buckets that deliberately serve read-only static content.
- Values operators set (`.tfvars`, pipeline settings, constants): server-controlled.
  Confirm an attacker-influenced source before calling anything injection.
- Placeholders, documentation sample keys, `examples/` and `test/` directories.
- A public EKS endpoint restricted to specific `public_access_cidrs`.

---

## References

- [Terraform AWS provider documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [GitHub Docs: Configuring OpenID Connect in Amazon Web Services](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- [AWS: confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [Checkov CLI reference](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [OWASP Top 10:2025](https://owasp.org/Top10/)
