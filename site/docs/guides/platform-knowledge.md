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
| `InsecureSkipVerify` | TLS certificate verification enabled | RESTRICTIVE |
| `InsecureSkipNonce` | OIDC nonce validation enabled (replay protection active) | RESTRICTIVE |
| `ServiceAccountName` | Use default service account | NEUTRAL |

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
