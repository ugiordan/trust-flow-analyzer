# Output Format

trust-flow-analyzer produces a single markdown file. The format is designed to be both human-readable and machine-parseable by LLM agents.

## Structure

```
# Trust Flow Map: {project}

## Authentication Flows
### Path: {name}
...

## Configuration Defaults
| Field | Library Default | Operator Default | Platform Meaning |
...

## Contract Violations
### {file}:{function} (line {n})
...

## Error Propagation
Total error creation points: {n}
Dropped errors: {n}
...

## Resource Lifecycles
### {resource}
...

## Assumption Contradictions
### {ID}: {title}
...
```

## Section details

### Authentication Flows

Each path includes:

- **Entry**: the HTTP handler entry point (file, function, line)
- **Authentication**: the authn checkpoint (or NONE)
- **Session**: session creation/retrieval points
- **Authorization**: the authz checkpoint (or NONE)
- **Validators**: additional validation checkpoints (email, group, domain)
- **Combined posture**: RESTRICTIVE, PERMISSIVE, or PARTIAL

### Configuration Defaults

Markdown table with columns:

- **Field**: type-qualified field name
- **Library Default**: value set in the source code
- **Operator Default**: whether the operator changes it
- **Platform Meaning**: what the value means in K8s context

### Assumption Contradictions

Each contradiction includes:

- **ID**: stable sequential identifier (CONTRADICTION-001, etc.)
- **Title**: one-line summary
- **Assumptions**: list of locations and what each component assumes
- **Combined**: the actual combined effect
- **Severity**: HIGH, MEDIUM, or LOW
- **Mitigation**: any known mitigating factor (if applicable)
