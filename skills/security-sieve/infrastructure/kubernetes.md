<!-- SPDX-License-Identifier: Apache-2.0 -->
# Kubernetes and Helm Security Reference

## Overview

Manifests, Helm charts and EKS settings decide who can run code on a node, who can read secrets and what a compromised pod can reach. Most hits in this area are missing hardening, which is **not** reportable. A finding needs a concrete path: a manifest that gives a pod host-level access, an RBAC rule that lets a low-privilege subject become admin, a committed secret, or a service an attacker reaches without authentication.

Load for: workload manifests, `Role`/`ClusterRole`/bindings, `Ingress`/`Service`, admission webhooks, Helm charts, EKS access settings. General IAM: `cloud.md`. Image build: `docker.md`. Chart and image supply chain: `references/supply-chain.md`.

Severity depends on reachability. A privileged pod that only cluster admins can deploy differs from a template any tenant can instantiate. Establish who can create the object first.

---

## Do not flag

Read this first. This skill reports high-confidence, exploitable findings only.

| Pattern | Why it is not a finding |
|---------|-------------------------|
| Missing `readOnlyRootFilesystem`, `runAsNonRoot`, `seccompProfile`, `capabilities.drop` | Lack of hardening alone. |
| No `NetworkPolicy` in a namespace | Absence alone is context. It raises the impact of another confirmed finding, nothing more. |
| Missing `resources.limits`/`requests` | Denial of service is out of scope. |
| `privileged`, `hostNetwork`, `hostPath` in a DaemonSet of a known system component: CNI (Cilium, Calico, aws-node), CSI node plugins, node-exporter, log shippers (Fluent Bit, Vector), kube-proxy, device plugins | Expected. Check image, name, namespace and owning chart before flagging. Flag only if the workload is unknown, application code, or a tenant-deployable template. |
| `image: foo:latest` or a tag without digest | Hygiene, low at best. Report only for an untrusted registry on a privileged or secret-holding workload. |
| `automountServiceAccountToken` at its default | Default behavior. Matters only if the bound SA has dangerous RBAC. |
| Placeholder secrets (`changeme`, `<REPLACE>`, `{{ .Values.x }}`) | Not a real credential. |
| Examples, `hack/`, `e2e/`, local `kind`/`minikube` manifests | Out of scope unless asked. |
| `cluster-admin` for a documented break-glass group or a scoped platform role | Intended admin access. Check owner and purpose. |
| Operator-set Helm values, `--set` from a trusted pipeline | Server-controlled, as in `SKILL.md`. |

A "verify" step below is part of the finding. A hit without it goes to Needs Verification.

---

## Pod Security Standards

Three levels: `privileged` (unrestricted), `baseline` (blocks known escalations), `restricted` (hardened). Pod Security Admission applies them per namespace through labels. See [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/) and [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/).

CWE-250, CWE-269. OWASP Top 10:2025 A02 Security Misconfiguration (escape paths also A01 Broken Access Control).

### Privileged containers and host namespaces

```yaml
# VULNERABLE: full host access in a tenant-deployable workload
spec:
  hostPID: true
  hostNetwork: true
  containers:
    - name: shell
      image: registry.example.com/tools/shell:1.4
      securityContext:
        privileged: true

# SAFE
spec:
  containers:
    - name: web
      image: registry.example.com/web:1.4
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
```

| Setting | Effect for code already running in the pod |
|---------|--------------------------------------------|
| `privileged: true` | All capabilities and host devices, relaxed seccomp/AppArmor. Trivial node escape. |
| `hostPID: true` | Sees and signals host processes. With `SYS_PTRACE`: reads host process memory and environment. |
| `hostIPC: true` | Shares host IPC and shared memory. |
| `hostNetwork: true` | Uses the node network stack. Reaches node-local services (kubelet, loopback endpoints, sometimes IMDS). |
| `allowPrivilegeEscalation: true` | Allows setuid-style gains. Alone it is hardening, not a finding. |

Report when the workload is not a known system component **and** a non-admin can deploy it, or the image is application code.

### hostPath and runtime sockets

```yaml
# VULNERABLE: runtime socket, host root or kubelet state mounted writable
volumes:
  - { name: sock, hostPath: { path: /var/run/docker.sock } }
  - { name: host, hostPath: { path: / } }
# EXPECTED: read-only /var/log for a log shipper (readOnly: true)
```

A mounted `docker.sock`, `containerd.sock`, `crio.sock` or a writable `/var/lib/kubelet` lets the container start privileged containers or read every pod's service account token on the node. Critical for application or tenant-deployable workloads. Medium or lower for a CI build agent whose purpose is building images (mention rootless builders).

### Capabilities, non-root, seccomp

```yaml
# VULNERABLE on application code
securityContext:
  capabilities:
    add: ["SYS_ADMIN"]     # also ALL, SYS_MODULE, SYS_PTRACE with hostPID

# SAFE (restricted profile)
securityContext:
  runAsNonRoot: true
  seccompProfile: { type: RuntimeDefault }
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities: { drop: ["ALL"] }
```

`NET_ADMIN`/`NET_RAW` allow packet spoofing on the pod network but are expected for CNI, VPN sidecars and mesh init containers, so check the owner first. Explicit weakenings (`runAsUser: 0`, `runAsNonRoot: false`, `seccompProfile.type: Unconfined`) are context, relevant only with another confirmed path. Missing fields are not findings.

### Grep patterns

```bash
rg -n 'privileged:\s*true|hostPID:\s*true|hostIPC:\s*true|hostNetwork:\s*true' --glob '*.{yaml,yml,tpl}'
rg -n 'docker\.sock|containerd\.sock|crio\.sock|/var/lib/kubelet|SYS_ADMIN' --glob '*.{yaml,yml,tpl}'
```

## RBAC

See [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/) and [Using RBAC authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).

CWE-269, CWE-266. OWASP Top 10:2025 A01 Broken Access Control.

Always establish **who holds the permission** and how privileged they already are. A rule granted only to `cluster-admin` is not an escalation.

### Wildcards

```yaml
# VULNERABLE: wildcard bound to a workload ServiceAccount
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]

# SAFE: namespaced Role with explicit resourceNames and verbs
```

Wildcards also cover future CRDs. Operators (cert-manager, Argo CD, Crossplane) hold broad rules legitimately: compare with the upstream chart before flagging.

### Escalation permissions

| Permission | Why it escalates |
|------------|------------------|
| `escalate` on roles/clusterroles | Create or edit roles beyond your own rights. The documented exception to the built-in escalation check. |
| `bind` on roles/clusterroles | Create bindings to roles you do not hold. Same documented exception. |
| `impersonate` on users/groups/serviceaccounts | Act as another identity, including a `system:masters` member if unrestricted. |
| `create` on pods or workload controllers | See next subsection. |
| `get`/`list`/`watch` on `secrets`, cluster-wide | `list` and `watch` return secret contents, not only `get`. |
| `create` on `serviceaccounts/token` | Mint tokens for ServiceAccounts in scope. |
| `create`/`get` on `nodes/proxy` | Reaches the kubelet API through the API server (unverified: exact exec behavior depends on kubelet authorization and version; confirm before reporting). |
| `update`/`patch` on webhook configurations | Intercept or alter any admission request. |
| `pods/exec`, `pods/attach` in sensitive namespaces | Command execution in existing pods. Check which namespaces. |

```yaml
# VULNERABLE: workload SA can mint admin
rules:
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources: ["clusterroles", "clusterrolebindings"]
    verbs: ["create", "update", "bind", "escalate"]

# SAFE impersonation names one identity: resourceNames: ["ci-readonly"]
```

### `create pods` is a node escalation path

Whoever can create pods (or controllers that create pods) in a namespace can, unless admission blocks it, mount host paths, run privileged, or mount any Secret and ServiceAccount of that namespace. The Kubernetes docs state that a user who can create a Pod using a Secret can see the Secret's value.

Report when a low-privilege subject (developer group, CI ServiceAccount, tenant role) holds `create` on pods or workload controllers **and** the namespace has no enforcing Pod Security level or admission policy (Kyverno, Gatekeeper, ValidatingAdmissionPolicy). Without that check it is Needs Verification.

### Cluster-wide secret read

```yaml
# VULNERABLE when bound by ClusterRoleBinding to an ordinary application SA
kind: ClusterRole
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
```

This exposes every Secret in every namespace. Legitimate holders: cert-manager, external-secrets, ingress controllers (TLS), Vault injectors. An ordinary application is a finding.

### system:masters and cluster-admin

`system:masters` bypasses all RBAC and authorization webhooks, and removing bindings does not revoke it.

```yaml
# VULNERABLE (Critical): everyone or every pod is admin
subjects:
  - kind: Group
    name: system:authenticated     # or system:unauthenticated, system:serviceaccounts
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin
```

### Default ServiceAccount

A dangerous role bound to the namespace `default` ServiceAccount (`subjects: - kind: ServiceAccount, name: default`) is inherited by every pod without `serviceAccountName`. Report when the role is dangerous per the table above. Prefer a dedicated SA with `automountServiceAccountToken: false` when the app never calls the API.

## Secrets

See [Good practices for Kubernetes Secrets](https://kubernetes.io/docs/concepts/security/secrets-good-practices/). Commit history and CI leakage: `references/data-protection.md`.

CWE-798, CWE-312. OWASP Top 10:2025 A04 Cryptographic Failures (plain storage), A07 Authentication Failures (committed credentials).

```yaml
# VULNERABLE: literal credential in a manifest
env:
  - name: DB_PASSWORD
    value: "pr0d-S3cret-2024"

# VULNERABLE: credential in a ConfigMap
kind: ConfigMap
data:
  database_url: "postgres://app:Xk29fJq@db.internal:5432/app"

# VULNERABLE: base64 is encoding, not encryption. Decode before judging.
kind: Secret
data:
  password: cHIwZC1TM2NyZXQtMjAyNA==

# SAFE: reference, value stored elsewhere
env:
  - name: DB_PASSWORD
    valueFrom:
      secretKeyRef: { name: app-db, key: password }
```

Report when the literal or decoded value is a plausible real credential (known provider prefix, high-entropy token, non-placeholder password) in a committed file. `stringData:` is the same. A ConfigMap is not access-controlled like a Secret and is often readable more broadly.

### Good patterns (do not flag)

External Secrets Operator (`ExternalSecret` with `remoteRef` into a store), Secrets Store CSI driver (`csi: driver: secrets-store.csi.k8s.io`), Sealed Secrets and SOPS (ciphertext in git) keep the value out of the repository. Do not comment on an operator's API version: not a security matter.

Etcd encryption at rest: without it Secrets are only base64 in etcd. On a managed cluster its absence is context. It matters when a self-managed control plane config in the repository lists only the `identity` provider for `secrets`.

## NetworkPolicy

A missing `NetworkPolicy` is **context, not a finding**. Use it to raise the severity of another confirmed finding (an exposed internal admin UI is worse on a flat pod network). Policies only take effect if the CNI enforces them. A policy that contradicts a stated intent (`from: ipBlock: 0.0.0.0/0` guarding a database) is worth a note. See [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

---

## Service and Ingress exposure

CWE-306, CWE-668. OWASP Top 10:2025 A02 Security Misconfiguration, A07 Authentication Failures.

### Admin interfaces

```yaml
# VULNERABLE: unauthenticated admin UI on a public load balancer
kind: Service
spec:
  type: LoadBalancer
  ports:
    - { port: 80, targetPort: 9090 }
# Backing app examples: Kubernetes Dashboard, Prometheus, Alertmanager,
# Grafana with anonymous admin, Argo CD, Jaeger, Kibana, etcd

# SAFE: internal scheme (AWS Load Balancer Controller annotation; verify against the installed version)
metadata:
  annotations:
    service.beta.kubernetes.io/aws-load-balancer-scheme: internal
```

Report only when **both** hold: the Service or Ingress is externally reachable (public LB scheme, public node addresses, public ingress host), **and** the backing application has no authentication or a default one. Check `loadBalancerSourceRanges`, security groups and ingress auth annotations first. A NodePort on nodes without public addresses is not exposure.

An internal tool (Prometheus, Alertmanager) published through an `Ingress` on a public class without an auth layer (oauth2-proxy, OIDC, mesh policy, `nginx.ingress.kubernetes.io/auth-url`) is the same finding.

### ingress-nginx: snippet injection (CVE-2021-25742)

A user who can create or update `Ingress` objects can use `nginx.ingress.kubernetes.io/configuration-snippet` or `server-snippet` to inject nginx configuration and read the controller's ServiceAccount token, which can read Secrets cluster-wide. Upstream says upgrading alone does not fix it. It is mitigated in v0.49.1 and later, and v1.0.1 and later, by setting `allow-snippet-annotations` to `"false"` in the controller ConfigMap; in the Helm chart that is `controller.allowSnippetAnnotations: false`. Sources: [kubernetes/kubernetes#126811](https://github.com/kubernetes/kubernetes/issues/126811), [GHSA-4pp2-3663-mcw8](https://github.com/advisories/GHSA-4pp2-3663-mcw8).

```yaml
# VULNERABLE when non-admins can write Ingress objects
controller:
  allowSnippetAnnotations: true
```

Report when snippets are enabled **and** subjects who can create `ingresses` include non-admins (check RBAC). Where only cluster admins or a trusted GitOps controller write Ingress, it is Needs Verification or dropped.

### ingress-nginx: admission webhook RCE (CVE-2025-1974, "IngressNightmare")

The validating admission webhook let an unauthenticated attacker with access to the pod network run code in the controller and so disclose Secrets it can read. Kubernetes rates it CVSS 9.8. Fixed in v1.11.5 and v1.12.1. Before upgrading it can be mitigated by disabling the validating admission controller. Sources: [Kubernetes blog](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/), [kubernetes/kubernetes#131009](https://github.com/kubernetes/kubernetes/issues/131009), [GHSA-mgvx-rpfc-9mpv](https://github.com/advisories/GHSA-mgvx-rpfc-9mpv).

```yaml
# VULNERABLE: controller older than 1.11.5 (1.11 line) / 1.12.1 (1.12 line), webhook on
controller:
  image:
    tag: v1.11.2
  admissionWebhooks:
    enabled: true
```

Report only with version evidence (pinned image tag, chart version or `appVersion`) plus the webhook enabled. Floating tags or unresolved versions are Needs Verification. Bounds for versions older than 1.11 are not covered here (unverified; read the advisory).

The project was announced for retirement in March 2026, with no later security patches ([announcement](https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/), [statement](https://kubernetes.io/blog/2026/01/29/ingress-nginx-statement/)). An ingress-nginx deployment is a context note, not a finding by itself.

## Admission webhooks

See [Dynamic Admission Control](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/). CWE-636 (failing open). OWASP Top 10:2025 A02 Security Misconfiguration.

```yaml
# CHECK: security-policy webhook that fails open
kind: ValidatingWebhookConfiguration
webhooks:
  - name: policy.example.com
    failurePolicy: Ignore     # requests pass when the webhook is down
# SAFE for an enforcement webhook: failurePolicy: Fail
```

`Ignore` on a webhook that enforces security (Kyverno, Gatekeeper) lets an attacker bypass it by making the webhook unavailable. That needs a precondition, so report as Needs Verification unless the attacker can disrupt the webhook or its backend. `Ignore` on a convenience mutating webhook is expected. `namespaceSelector` exclusions that exempt tenant namespaces carry the same weight.

## Images

CWE-829. OWASP Top 10:2025 A03 Software Supply Chain Failures. A mutable tag (`:latest`) or missing digest is hygiene. Report only a mutable tag from a registry namespace you do not control on a privileged or secret-holding workload. Build content: `docker.md`. Registry and CI trust: `references/supply-chain.md`.

## EKS specifics

See [EKS best practices: identity and access management](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html) and [EKS access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html). IAM policy review: `cloud.md`.

CWE-269, CWE-732. OWASP Top 10:2025 A01 Broken Access Control.

### Pod AWS credentials: IRSA / Pod Identity vs node role

The AWS guide says a pod using IRSA or Pod Identity "can still inherit the rights of the instance profile assigned to the worker node", and recommends IMDSv2 required with hop limit 1 for pods that do not need node permissions. It also says the default `aws-node` DaemonSet uses the instance role (recommending IRSA or Pod Identity for it), and that pods which need IMDS require hop limit 2.

```hcl
# CHECK: reachable from pods, IMDSv1 allowed
metadata_options { http_tokens = "optional", http_put_response_hop_limit = 2 }
# SAFE for nodes whose pods use IRSA / Pod Identity: http_tokens = "required", hop limit 1
```

This is **context unless the node role is over-privileged**. Report only when pods can reach IMDS (hop limit above 1, or `hostNetwork` pods) **and** the node role carries more than node basics (`iam:*`, `secretsmanager:GetSecretValue`, broad `s3:*`, `ec2:*`). Hop limit 2 on a node role with only managed EKS policies is a note; some add-ons need it.

IRSA trust policies must be scoped to one service account (`:sub`) and audience (`:aud`):

```json
// VULNERABLE: any service account in the cluster can assume the role
"Condition": { "StringLike": { "<oidc-provider>:sub": "system:serviceaccount:*:*" } }

// VULNERABLE: no :sub condition
"Condition": { "StringEquals": { "<oidc-provider>:aud": "sts.amazonaws.com" } }

// SAFE
"Condition": { "StringEquals": {
  "<oidc-provider>:aud": "sts.amazonaws.com",
  "<oidc-provider>:sub": "system:serviceaccount:app:web" } }
```

Pod Identity trusts the `pods.eks.amazonaws.com` principal. With ABAC on its session tags, a policy must check cluster ARN and namespace as well as service account name, since service account names are unique only within a namespace and cluster. An `eks.amazonaws.com/role-arn` annotation naming a high-privilege role on an SA that tenants can use is a path from "can create a pod" to AWS privileges.

### aws-auth and access entries

`aws-auth` in `kube-system` statically maps IAM principals to Kubernetes groups. AWS documents it as deprecated in favor of access entries, managed through the EKS API with predefined policies (`AmazonEKSClusterAdminPolicy`, `AmazonEKSAdminPolicy`, `AmazonEKSEditPolicy`, `AmazonEKSViewPolicy`).

```yaml
# VULNERABLE: broad role mapped to cluster admin
kind: ConfigMap
metadata: { name: aws-auth, namespace: kube-system }
data:
  mapRoles: |
    - rolearn: arn:aws:iam::111122223333:role/developers
      username: dev
      groups:
        - system:masters
```

Report when a role or user that is not a platform-admin or break-glass identity is mapped to `system:masters` or cluster-scope `AmazonEKSClusterAdminPolicy`. Verify who can assume that role (trust policy) and what it is for. A CI role that is the cluster's only deployer is expected. A role with broad trust (`"AWS": "*"`, a whole account) plus cluster admin is a finding.

Context, not findings: the cluster creator principal gets permanent admin in `CONFIG_MAP` mode and can be removed with `bootstrapClusterCreatorAdminPermissions=false` in `API` or `API_AND_CONFIG_MAP` mode; role mappings without `{{SessionName}}` in `username` hide the real user in audit logs; `mapUsers` entries imply IAM users. Whether EKS accepts `system:masters` as a group on access entries: unverified, check current EKS documentation before stating it.

---

## Helm

See [Helm chart best practices](https://helm.sh/docs/chart_best_practices/), [template functions](https://helm.sh/docs/chart_template_guide/function_list/), [chart tips: tpl](https://helm.sh/docs/howto/charts_tips_and_tricks/).

CWE-94, CWE-532, CWE-798. OWASP Top 10:2025 A05 Injection, A02 Security Misconfiguration.

Values are normally operator-controlled. Template injection matters only when **a lower-privileged actor controls the values**: a tenant who edits a `HelmRelease` or Argo CD `Application` values field, a self-service portal, a CRD that feeds a Helm renderer. Establish the values source first.

### `tpl` on user-supplied values

`tpl` evaluates a string as a template against the chart context, reaching `.Values`, `.Release`, `.Files` and `lookup`.

```yaml
# VULNERABLE when a tenant controls .Values.extraConfig
data:
  config.yaml: {{ tpl .Values.extraConfig . | quote }}
# tenant supplies:
#   extraConfig: '{{ (lookup "v1" "Secret" "kube-system" "admin-token").data | toJson }}'

# SAFE: value as data
data:
  config.yaml: {{ .Values.extraConfig | quote }}
```

`tpl` on operator-owned values is a documented, legitimate pattern: do not flag it. In multi-tenant GitOps where tenants own values, it is High to Critical depending on what the Helm runner can read.

### Secrets rendered into ConfigMaps

```yaml
# VULNERABLE: templates/configmap.yaml
data:
  DB_PASSWORD: {{ .Values.db.password | quote }}

# SAFE: Secret, or an existingSecret reference
{{- if not .Values.db.existingSecret }}
kind: Secret
stringData:
  password: {{ required "db.password is required" .Values.db.password | quote }}
{{- end }}
```

A non-empty default credential in `values.yaml` (`adminPassword: changeme`, `secretKey: supersecret`) that ships unless overridden is a finding when the chart is the deployed artifact and the credential protects a reachable service. An empty default with `required` is fine.

### Chart defaults that disable security

Defaults such as `securityContext.privileged: true`, `auth.enabled: false` on an admin UI, or `service.type: LoadBalancer` are findings only if they reach a template. Run `helm template` with each environment's values and review the output. For third-party charts report only defaults this repository inherits into a reachable production deployment.

### Secrets in CI logs

```bash
# VULNERABLE: secret on the command line, or --debug printing computed values
helm upgrade --install app ./chart --set db.password=hunter2
helm upgrade --install app ./chart --set db.password="$DB_PASSWORD" --debug

# SAFE: values file from a secret store, never echoed
helm upgrade --install app ./chart -f /secure/values-secret.yaml
```

Report a literal secret in a committed pipeline file. A masked CI variable is a note unless the job uses `--debug` or `set -x`. Helm stores release values (secrets included) in a Secret in the release namespace by default, so read access to Secrets there exposes them (see RBAC). Hook Jobs (`helm.sh/hook`) run with the chart's ServiceAccount: review them as normal workloads.

## Testing checklist

- [ ] No application pod with privileged mode, host namespaces, runtime sockets or writable sensitive `hostPath`
- [ ] No wildcard RBAC, `escalate`, `bind`, open `impersonate`, or cluster-wide `secrets` read for non-admin subjects
- [ ] `create pods` holders confined by Pod Security Admission or a policy engine
- [ ] No real credentials in manifests, ConfigMaps, `values.yaml` or pipeline files
- [ ] No unauthenticated admin interface on a public Service or Ingress
- [ ] ingress-nginx snippets off where tenants write Ingress; version past the CVE-2025-1974 fix if the webhook is on
- [ ] IRSA trust scoped to one service account; no broad role mapped to `system:masters`
- [ ] Helm: no `tpl` on tenant-controlled values, no secrets in ConfigMaps
- [ ] Each finding names who the attacker is, what they control and what they gain

## References

- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [Good practices for Kubernetes Secrets](https://kubernetes.io/docs/concepts/security/secrets-good-practices/)
- [Ingress-nginx CVE-2025-1974](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- [Amazon EKS best practices: IAM](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html)
- [Helm chart best practices](https://helm.sh/docs/chart_best_practices/)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
