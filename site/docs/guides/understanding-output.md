# Understanding Output

The trust flow map is a markdown document with six sections. Each section corresponds to one analysis pass, plus a final synthesis section.

## Authentication Flows

Each auth flow represents a distinct code path from HTTP entry point to access decision.

```markdown
### Path: handler.ProxyHandler
Entry: handler.go:ServeHTTP (line 11)
Authentication: auth.go:ValidateToken (line 5)
Authorization: auth.go:Authorize (line 12)
Combined posture: RESTRICTIVE
```

**Posture values:**

| Posture | Meaning |
|---------|---------|
| RESTRICTIVE | Has both authentication and authorization |
| PERMISSIVE | Has authentication but no authorization gate |
| PARTIAL | Has authorization but no authentication |

!!! warning "PERMISSIVE posture"
    A PERMISSIVE posture means any valid credential grants full access. This is the pattern behind most auth bypass vulnerabilities in K8s operators.

## Configuration Defaults

A table showing what empty/nil/zero values mean for security-critical fields.

```markdown
| Field | Library Default | Operator Default | Platform Meaning |
|-------|----------------|-----------------|------------------|
| audiences | nil | nil (unchanged) | Accept API server audience |
| AllowedGroups | nil | nil (unchanged) | Authorize all authenticated users |
```

Fields are type-qualified (e.g., `pkg/options.Provider.AllowedGroups`) to avoid false positives from common field names.

## Contract Violations

Functions returning errors whose callers don't check the error.

```markdown
### auth.go:ValidateToken (line 5)
Returns: (string, error (error) (nillable))

- **UNCHECKED_ERROR**: ServeHTTP does not check error from ValidateToken
```

This is the most common source of fail-open vulnerabilities: an auth function returns an error, but the caller ignores it and proceeds as if authentication succeeded.

## Error Propagation

Every error creation point (`errors.New`, `fmt.Errorf`) and how it's handled.

- **HANDLED / CLOSED**: error is returned or logged, execution stops on the error path
- **DROPPED / OPEN**: error is silently discarded, execution continues (fail-open risk)

## Resource Lifecycles

K8s resource creation, ownership, and cleanup chains.

```markdown
### ConfigMap
Create: reconciler.go:Reconcile (line 45)
Delete: NONE
Owner: reconciler.go:setOwnerRef (line 52)
Finalizer: NONE
```

Resources marked **ORPHANABLE** have no owner reference, finalizer, or explicit delete, meaning they'll leak if the parent is removed.

## Assumption Contradictions

The most important section. Each contradiction identifies a cross-file assumption violation.

```markdown
### CONTRADICTION-001: proxy path has no effective authorization gate
- auth.go:ValidateToken ASSUMES: ValidateToken authenticates the request
- handler.go:ServeHTTP ASSUMES: ServeHTTP has no authorization gate
- Combined: Authentication success equals authorization.
- Severity: HIGH
```

Contradictions are sorted by severity (HIGH first) and assigned stable IDs.
