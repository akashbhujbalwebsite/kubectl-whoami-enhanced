# kubectl whoami-enhanced

A kubectl plugin that shows **who you are** and **what you can do** in a Kubernetes cluster — identity, token expiry, permission matrix, and the Role/RoleBinding that grants each permission, all in one command.

## Installation

```bash
kubectl krew install whoami-enhanced
```

## Usage

```bash
# Check identity and permissions in the current namespace
kubectl whoami-enhanced

# Check a specific namespace
kubectl whoami-enhanced -n production

# Check all namespaces
kubectl whoami-enhanced -A

# JSON output (for scripting/CI)
kubectl whoami-enhanced -n default --output-json
```

## Example Output

```
 KUBECTL WHOAMI — Enhanced
───────────────────────────────────────────────────────
 Context:    my-cluster
 User:       jane@example.com
 Groups:     dev-team, system:authenticated
 Namespace:  staging
 Token:      expires in 5h 23m (at 2026-06-25 18:00:00)
───────────────────────────────────────────────────────
 PERMISSIONS
───────────────────────────────────────────────────────
 VERB       RESOURCE             ACCESS REASON
 get        pods                 ✓      ClusterRole/view → ClusterRoleBinding/dev-team-view
 list       pods                 ✓      ClusterRole/view → ClusterRoleBinding/dev-team-view
 delete     pods                 ✗      no matching rule found
 exec       pods                 ✗      no matching rule found
 get        deployments          ✓      ClusterRole/view → ClusterRoleBinding/dev-team-view
 create     deployments          ✗      no matching rule found
 delete     deployments          ✗      no matching rule found
 get        secrets              ✗      no matching rule found
 get        configmaps           ✓      ClusterRole/view → ClusterRoleBinding/dev-team-view
 get        nodes                ✗      no matching rule found
───────────────────────────────────────────────────────
 NOTE: v0.1.0 checks core resources only. CRDs not included.
───────────────────────────────────────────────────────
```

## What it does

| Feature | Description |
|---------|-------------|
| Identity | Context, user, groups (with auth-method explanation when groups unavailable) |
| Token TTL | JWT expiry parsed and displayed as a human-readable countdown |
| Permission matrix | 10 verb/resource checks with correct API groups |
| REASON column | Which Role/RoleBinding grants each allowed permission |
| Graceful degradation | REASON falls back cleanly when RBAC read access is missing |
| `--all-namespaces` | Checks permissions across every namespace |
| `--output-json` | Full structured output including `granted_by` for scripting |

## Why not just use existing tools?

| Tool | Identity | Permissions | Token TTL | REASON |
|------|----------|-------------|-----------|--------|
| `kubectl whoami --all` | ✓ | ✗ | ✗ | ✗ |
| `kubectl access-matrix` | ✗ | ✓ | ✗ | ✗ |
| `kubectl auth whoami` | ✓ | ✗ | ✗ | ✗ |
| **kubectl whoami-enhanced** | ✓ | ✓ | ✓ | ✓ |

## Required permissions (RBAC footprint)

All calls are read-only — no writes or mutations.

| API call | When | Why |
|----------|------|-----|
| `authentication.k8s.io/tokenreviews` create | Token auth only | Resolves real username + groups |
| `authorization.k8s.io/selfsubjectaccessreviews` create | Always | Checks each permission |
| `rbac.authorization.k8s.io/rolebindings` list | REASON column | Finds namespace bindings |
| `rbac.authorization.k8s.io/clusterrolebindings` list | REASON column | Finds cluster-wide bindings |
| `rbac.authorization.k8s.io/roles` get | REASON column | Fetches role rules |
| `rbac.authorization.k8s.io/clusterroles` get | REASON column | Fetches cluster role rules |

`selfsubjectaccessreviews` is available to every authenticated user by default. The RBAC read calls are best-effort — if access is unavailable, the REASON column shows a clear message instead of failing.

## Caveats

- Groups are only shown with token-based auth (OIDC/ServiceAccount). Certificate-based auth will show a note explaining why.
- The REASON column shows the first matching binding when multiple bindings cover the same permission (v0.1 behaviour).
- v0.1.0 checks 10 core resource types. CRDs are not included.

## License

Apache 2.0
