<!-- SPDX-License-Identifier: Apache-2.0 -->
# Cloud Infrastructure Security Reference

IAM, service-to-service TLS, secrets, network and compliance for cloud-native
systems. Merged in from the former `security-engineer` skill. Dependency and
image CVEs: `references/threat-modeling.md` and `references/supply-chain.md`.

## IAM and Access Control

1. Audit existing IAM policies — flag any with `*` resource or `*` action.
2. Least privilege: each identity gets exactly the permissions it needs.
3. IAM roles for service-to-service auth. No long-lived access keys. OIDC federation for CI/CD.
4. Role assumption chain: `CI/CD → deploy role → specific resources only`.
5. Review with AWS IAM Access Analyzer or equivalent. Remove unused permissions.

## Mutual TLS

- Private CA: CFSSL, Vault PKI, or AWS Private CA for service certificates.
- Automate issuance and rotation: cert-manager in K8s, or Vault PKI with auto-renewal.
- Certificate lifetime: **24 hours** for service-to-service. Short TTL limits the compromise window.
- Terminate mTLS at the service mesh (Istio/Linkerd) or the load balancer.
- Revocation: OCSP stapling or CRL distribution.
- Validate the full chain on every connection. Reject self-signed and expired certificates.

## Secrets Management

- One source of truth: HashiCorp Vault, AWS Secrets Manager, or GCP Secret Manager.
- Store DB credentials, API keys, TLS certificates and encryption keys with per-service access policies.
- **Dynamic secrets**: Vault issues temporary DB credentials with a TTL, revoked on expiry.
- Rotation on a schedule, without application downtime.
- Full audit log: who read which secret, and when.
- Vault transit engine: applications encrypt and decrypt without seeing the key.

## Vulnerability Management

| Target | Tool | Action on fail |
|--------|------|----------------|
| Container images | Trivy, Grype, Snyk | Block deploy on critical/high CVE |
| IaC configs | Checkov, tfsec | Fail CI on misconfigurations |
| Dependencies | `npm/pip/cargo audit` | Fail build on critical |
| Internet-facing services | Penetration testing | Quarterly external assessment |

**SLA**: Critical CVEs 24h. High 7 days. Medium 30 days. Triage a finding before
counting it: `references/threat-modeling.md` → Dependency Vulnerabilities.

## Network Security

- Zero trust: authenticate and authorize every request regardless of network location.
- VPC private endpoints for cloud services — traffic stays off the public internet.
- Detection: GuardDuty (AWS), Falco (K8s) for suspicious network and container behaviour.
- Egress filtering: workloads reach only approved external endpoints.
- WAF with OWASP Top 10 rules for public-facing services.

## Compliance and Audit

- Continuous compliance: AWS Config rules or Azure Policy against security baselines.
- Map controls to frameworks: SOC 2, ISO 27001, PCI DSS, HIPAA.
- Asset inventory: owner, data classification, applicable requirements.
- Centralized logging with tamper-proof storage. Retention per framework (1–7 years).

## Checklist for an infrastructure change

- [ ] Checkov/tfsec run on every modified infrastructure config
- [ ] IAM policies verified least-privilege (Access Analyzer or equivalent)
- [ ] Secrets in the vault — not in files or environment variables
- [ ] mTLS between affected services tested: valid, properly chained certificates
