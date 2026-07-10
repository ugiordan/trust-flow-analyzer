# Output Format

trust-flow-analyzer produces either a markdown file or JSON output. The markdown format is designed to be both human-readable and machine-parseable by LLM agents. The JSON format provides the full analysis result as a structured object.

## Markdown Structure

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

## Secret Exposures
### {file}:{line}
...

## Auth Policies
### {policy name} ({kind})
...

## Route Coverage
| Route | Kind | Policy | Covered | Mechanism |
...

## Network Policies
### {policy name}
...

## RBAC Findings
### {role name} ({kind})
...

## Mesh Policies
### {policy name} ({kind})
...

## Template Risks
### {file}:{line}
...

## Webhook Defaults
### {function}
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

### Secret Exposures

Each finding includes:

- **File and line**: location of the secret exposure
- **Pattern**: classification (ENV_IN_ARGS, HARDCODED_SECRET)
- **Field**: the variable or field name involved
- **Description**: what the exposure looks like

### Auth Policies

Each policy includes:

- **Name**: the resource name from the YAML manifest
- **Kind**: AuthPolicy, AuthConfig, AuthorizationPolicy, or RegoPolicy
- **File**: source YAML file
- **Target ref**: the workload or gateway the policy targets
- **Rules**: list of authentication, authorization, and metadata rules
- **Skip paths**: paths excluded from auth enforcement

### Route Coverage

Markdown table mapping routes to their auth policy coverage:

- **Route**: the route resource name
- **Route kind**: HTTPRoute or Ingress
- **Policy**: the covering auth policy name, or "NONE"
- **Covered**: whether the route has auth coverage
- **Mechanism**: how coverage is determined (direct, fallback, gateway-default, INTENTIONAL)
- **Backend**: the backend service targeted by the route

### Network Policies

Each policy includes:

- **Name**: the NetworkPolicy resource name
- **File**: source YAML file
- **Namespace**: the namespace the policy applies to
- **Pod selector**: label selector as string
- **Policy types**: Ingress, Egress, or both
- **Ingress from**: summarized ingress source descriptions
- **Egress to**: summarized egress destination descriptions

### RBAC Findings

Each finding includes:

- **Name**: the ClusterRole or ClusterRoleBinding name
- **Kind**: ClusterRole or ClusterRoleBinding
- **File**: source YAML file
- **Severity**: HIGH, MEDIUM, or LOW
- **Rule**: which RBAC rule is overprivileged
- **Reason**: explanation of why the rule is flagged

### Mesh Policies

Each policy includes:

- **Name**: the mesh policy resource name
- **Kind**: PeerAuthentication, DestinationRule, ServiceMeshMemberRoll, or ServiceMeshControlPlane
- **File**: source YAML file
- **Namespace**: the namespace scope
- **mTLS mode**: STRICT, PERMISSIVE, DISABLE, or UNSET
- **Scope**: namespace-wide, workload-specific, or mesh-wide

### Template Risks

Each finding includes:

- **File and line**: location of the template risk
- **Kind**: SECRET_IN_ARGS, CONDITIONAL_SECURITY, or HARDCODED_CREDENTIAL
- **Description**: what the risk pattern looks like
- **Field**: the template field or env var involved
- **Severity**: HIGH, MEDIUM, or LOW

### Webhook Defaults

Each finding includes:

- **Function**: the webhook Default() method name (e.g., `ModelRegistry.Default`)
- **File and line**: location of the defaulter method
- **Fields set**: security-relevant fields the defaulter sets
- **Fields unset**: security-relevant fields the defaulter does NOT set

### Assumption Contradictions

Each contradiction includes:

- **ID**: stable sequential identifier (CONTRADICTION-001, etc.)
- **Title**: one-line summary
- **Assumptions**: list of locations and what each component assumes
- **Combined**: the actual combined effect
- **Severity**: HIGH, MEDIUM, or LOW
- **Mitigation**: any known mitigating factor (if applicable)

## JSON Format

When using `-format json`, the output is a single JSON object containing the full `AnalysisResult` structure. All sections from the markdown format are represented as arrays of typed objects.

```json
{
  "Project": "my-project",
  "AuthFlows": [...],
  "Defaults": [...],
  "Contracts": [...],
  "ErrorPaths": [...],
  "Lifecycles": [...],
  "SecretExposures": [...],
  "AuthPolicies": [...],
  "RouteCoverage": [...],
  "NetworkPolicies": [...],
  "RBACFindings": [...],
  "MeshPolicies": [...],
  "TemplateRisks": [...],
  "WebhookDefaults": [...],
  "Contradictions": [...]
}
```

Each contradiction in the JSON output has the same fields as the markdown format: `ID`, `Title`, `Severity`, `Assumptions`, `Combined`, and `Mitigation`.
