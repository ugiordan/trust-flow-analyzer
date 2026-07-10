# Analysis Passes

trust-flow-analyzer runs eleven analysis passes, then synthesizes contradictions across their results. The first five passes (AuthFlow, DefaultValue, Contract, ErrorProp, Lifecycle) operate on source code via SSA (Go) or tree-sitter (Python, TypeScript, Rust). The remaining six passes (Secrets, AuthPolicy, NetworkPolicy, RBAC Scope, mTLS Detection, Template Rendering) scan source files and YAML manifests directly.

## AuthFlow Pass

**Purpose**: trace credential arrival to access decision, group into distinct paths.

**How it works**:

1. Scans all module functions for names matching auth patterns (e.g., `ValidateToken`, `Authorize`, `CheckGroups`)
2. Finds HTTP entry points (methods named `ServeHTTP` with the correct signature)
3. For each entry point, performs forward BFS on the VTA call graph to find reachable auth functions
4. Groups reachable functions by kind (authn, authz, validator, session)
5. Determines posture based on which kinds are present

**Auth patterns detected**:

| Pattern | Kind |
|---------|------|
| Authenticate, ValidateToken, TokenReview, VerifyToken, CheckToken, WithAuthentication | authn |
| Authorize, CheckAccess, SubjectAccessReview, IsAllowed | authz |
| ValidateEmail, isEmailValid, ValidateDomain, CheckGroups | validator |
| CreateSession, createSession, GetSession, getAuthenticatedSession | session |

## DefaultValue Pass

**Purpose**: find what empty/nil/zero means at each configuration level.

**How it works**:

1. Walks AST of all module source files
2. For struct literal fields, checks if the field name matches the platform knowledge database
3. For flag definitions (`flag.String`, `pflag.StringVar`, etc.), extracts default values
4. Cross-references with platform semantics to determine permissiveness
5. Analyzes webhook `Default()` methods for security field coverage
6. Scans `params.env` files (kustomize overlays) for security-relevant configuration

**Type qualification**: uses `TypesInfo` to qualify field names as `StructType.FieldName` to avoid false positives.

### Webhook defaulting analysis

The pass finds webhook `Default()` methods via the SSA call graph and checks which security-relevant fields the defaulter sets or leaves unset. Fields tracked include auth proxy sidecars (KubeRBACProxy, OAuthProxy, Authorino), SSL modes, and other security components. When a webhook defaulter does not set these fields, it surfaces the gap as a `WebhookDefault` finding.

### params.env kustomize parsing

The pass walks the project for `params.env` files (commonly used in kustomize overlays). For each file, it parses `KEY=VALUE` lines and flags security-relevant keys (matching substrings like PASSWORD, SECRET, TOKEN, KEY) that are empty or unset. These appear as `DefaultValue` findings with `(empty) params.env (kustomize)` as the operator default.

## Contract Pass

**Purpose**: for functions returning errors, check if all callers handle the error.

**How it works**:

1. For each module function with an error return, finds all callers via call graph
2. For multi-return functions, checks if the caller extracts the error value (via SSA Extract instructions)
3. For single-return functions (just `error`), checks if any referrer uses the return value
4. For calls used as statements (all returns discarded), reports `UNCHECKED_ERROR`

## ErrorProp Pass

**Purpose**: trace error values from creation to handling.

**How it works**:

1. Finds error creation calls (`errors.New`, `fmt.Errorf`, etc.) using package-qualified matching
2. Traces direct referrers of the error value through SSA
3. Classifies each referrer as RETURN, LOG, WRAP, or DROP
4. Determines fail mode: CLOSED if the error is handled, OPEN if dropped

**Error creators matched** (by package path + function name):

- `errors.New`, `fmt.Errorf`
- `errors.Wrap`, `errors.Wrapf`, `errors.WithStack`, `errors.WithMessage`

## Lifecycle Pass

**Purpose**: trace K8s resource creation, ownership, and cleanup.

**How it works**:

1. Scans module functions for K8s client calls (Create, Delete, SetOwnerReference, AddFinalizer)
2. Verifies the callee belongs to a K8s client package (`sigs.k8s.io`, `k8s.io/client-go`, `controller-runtime`)
3. Infers the resource type from the call arguments (skipping `context.Context`)
4. Determines if the resource is orphanable (no owner, finalizer, or delete)

## Secrets Pass

**Purpose**: detect hardcoded secrets and secret exposure in source code.

**How it works**:

1. For Go projects (SSA mode): scans AST for string literals assigned to fields or variables with secret-related names (PASSWORD, SECRET, TOKEN, KEY)
2. Detects env var patterns like `$(DB_PASSWORD)` or `$(API_SECRET_KEY)` in string literals
3. Flags functions that pass secrets as arguments where they could be logged or exposed
4. Reports each finding with a pattern classification: `ENV_IN_ARGS`, `HARDCODED_SECRET`

## AuthPolicy Pass

**Purpose**: scan YAML manifests for authentication and authorization policy resources.

**How it works**:

1. Walks the project directory for YAML files
2. Parses each YAML document and checks the `kind` field against supported auth resource kinds: AuthPolicy, AuthConfig, AuthorizationPolicy, RegoPolicy
3. Extracts the policy name, target references, rules (authentication, authorization, metadata), and skip paths
4. Maps routes (HTTPRoute, Ingress) to their covering auth policies to compute route coverage
5. Reports uncovered routes (routes with no matching auth policy) for contradiction synthesis

## NetworkPolicy Pass

**Purpose**: extract Kubernetes NetworkPolicy resources and report their scope.

**How it works**:

1. Walks the project directory for YAML files
2. Parses NetworkPolicy resources, extracting namespace, pod selectors, and policy types (Ingress/Egress)
3. Summarizes ingress sources and egress destinations
4. Feeds into contradiction synthesis to detect namespaces without any network policy

## RBAC Scope Pass

**Purpose**: detect overprivileged RBAC patterns in ClusterRole and ClusterRoleBinding resources.

**How it works**:

1. Walks the project directory for YAML files
2. Parses ClusterRole and ClusterRoleBinding resources
3. Flags overprivileged patterns: wildcard verbs (`*`), cluster-wide secrets access, broad resource group grants
4. Assigns severity (HIGH, MEDIUM, LOW) based on the scope and nature of the privilege

## mTLS Detection Pass

**Purpose**: scan service mesh policy resources for mTLS configuration.

**How it works**:

1. Walks the project directory for YAML files
2. Parses Istio and OpenShift Service Mesh resources: PeerAuthentication, DestinationRule, ServiceMeshMemberRoll, ServiceMeshControlPlane
3. Extracts mTLS mode (STRICT, PERMISSIVE, DISABLE, UNSET) and scope (namespace-wide, workload-specific, mesh-wide)
4. Feeds into contradiction synthesis to flag PERMISSIVE or DISABLE modes

## Template Rendering Pass

**Purpose**: scan Go templates and templated YAML files for security-relevant patterns.

**How it works**:

1. Walks the project directory for template files (`.tmpl`, `.tpl`) and YAML files
2. Detects three risk categories:
    - **SECRET_IN_ARGS**: secrets expanded via `$(VAR)` patterns in container command/args fields
    - **CONDITIONAL_SECURITY**: security-critical sidecars or settings gated by template conditionals (`{{ if }}`)
    - **HARDCODED_CREDENTIAL**: literal credentials in template files
3. Each finding includes the file, line, risk kind, and severity

## Contradiction Synthesis

Runs after all passes. Detects ten types of cross-file contradictions:

1. **Auth without authz**: PERMISSIVE auth paths (authentication exists, authorization doesn't)
2. **Permissive defaults**: 2+ security-critical fields defaulting to permissive values
3. **Dropped errors on auth path**: errors created and silently dropped in auth-related functions
4. **Orphaned resources**: K8s resources created without ownership or cleanup
5. **Uncovered routes**: HTTPRoute or Ingress resources with no matching auth policy
6. **Missing network policies**: namespaces that deploy workloads but have no NetworkPolicy
7. **Overprivileged RBAC**: ClusterRoles or ClusterRoleBindings with excessive permissions
8. **Weak mTLS**: mesh policies using PERMISSIVE or DISABLE mTLS mode
9. **Template security risks**: secrets exposed in templates, conditional security sidecars
10. **Insecure webhook defaults**: webhook defaulters that do not set security-relevant fields

Contradictions are sorted by severity (HIGH > MEDIUM > LOW) then by title, and assigned stable sequential IDs.
