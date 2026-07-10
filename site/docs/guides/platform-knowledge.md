# Platform Knowledge

trust-flow-analyzer includes a built-in platform knowledge database that maps configuration field names to their security semantics. When a field is empty, nil, or zero, its meaning depends on the platform.

## Built-in K8s semantics

| Field | Empty/Zero Meaning | Permissiveness |
|-------|-------------------|----------------|
| `audiences` | Accept API server audience (all in-cluster pod SA tokens) | PERMISSIVE |
| `AllowedGroups` | Authorize all authenticated users | PERMISSIVE |
| `email-domain` / `EmailDomain` | Accept any email domain | PERMISSIVE |
| `AllowedOrganizations` | Accept users from any organization | PERMISSIVE |
| `Namespace` | Watch all namespaces (cluster-scoped) | PERMISSIVE |
| `sslMode` / `SslMode` | SSL/TLS mode for database connections. When set to `disable`, passwords transmitted in cleartext. | PERMISSIVE |
| `KubeRBACProxy` | No kube-rbac-proxy sidecar deployed. API endpoints have no auth. | PERMISSIVE |
| `OAuthProxy` | No OAuth proxy sidecar deployed. API endpoints have no auth. | PERMISSIVE |
| `Authorino` | No Authorino auth policy deployed. Service has no auth enforcement. | PERMISSIVE |
| `InsecureSkipVerify` | TLS certificate verification enabled | RESTRICTIVE |
| `InsecureSkipNonce` | OIDC nonce validation enabled (replay protection active) | RESTRICTIVE |
| `ServiceAccountName` | Use default service account | NEUTRAL |

## Auth proxy sidecar fields

The `KubeRBACProxy`, `OAuthProxy`, and `Authorino` fields are particularly important in the RHOAI ecosystem. Operators manage these auth proxy sidecars for their components:

- **KubeRBACProxy**: when nil/absent, the operator does not inject a kube-rbac-proxy sidecar. The application's API is exposed without authentication or authorization. This is the default auth mechanism for many RHOAI components.
- **OAuthProxy**: when nil/absent, the operator does not inject an OAuth proxy sidecar. The application's API is exposed without authentication.
- **Authorino**: when nil/absent, no Authorino-based auth policy is applied to the service. This is the auth mechanism used by models-as-a-service in RHOAI.

These fields are checked in the DefaultValue pass and also referenced by the webhook defaulting analysis (to determine which security fields a `Default()` method sets or skips).

## Database connection security

The `sslMode` / `SslMode` fields control SSL/TLS for database connections:

- When set to `disable`, database connections use plaintext and passwords are transmitted in cleartext
- The DefaultValue pass flags this as PERMISSIVE when the default is `disable` or empty (no encryption)
- This is relevant for model-registry-operator and similar components that connect to PostgreSQL backends

## params.env scanning

The DefaultValue pass scans `params.env` files used in kustomize overlays. These files contain `KEY=VALUE` pairs that configure component deployments. The tool detects security-relevant keys based on substring matching:

**Matched key substrings**: PASSWORD, SECRET, TOKEN, KEY

When a params.env file contains a security-relevant key that is empty or set to a placeholder value, the tool reports it as a configuration default with operator context.

Example from model-registry-operator:

```
# config/overlays/odh/params.env
DATABASE_PASSWORD=
DATABASE_SSL_MODE=disable
```

This produces two DefaultValue findings: an empty database password and a disabled SSL mode.

## How matching works

The defaults pass matches struct field names in composite literals and flag definitions against the knowledge base. Matching is type-qualified when type information is available:

1. First tries `StructType.FieldName` (e.g., `options.Provider.AllowedGroups`)
2. Falls back to raw field name (e.g., `AllowedGroups`)

This prevents false positives from common field names like `Namespace` appearing in unrelated structs.

## Extending the knowledge base

The knowledge base is in `pkg/platform/knowledge.go`. To add a new field:

```go
k.entries["NewField"] = FieldSemantics{
    Field:          "NewField",
    EmptyMeaning:   "What empty/nil means for this field",
    Permissiveness: "PERMISSIVE", // or RESTRICTIVE, NEUTRAL
    Description:    "Detailed explanation",
}
```
