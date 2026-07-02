# Analysis Passes

trust-flow-analyzer runs five analysis passes sequentially, then synthesizes contradictions across their results.

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

**Type qualification**: uses `TypesInfo` to qualify field names as `StructType.FieldName` to avoid false positives.

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

## Contradiction Synthesis

Runs after all passes. Detects four types of cross-file contradictions:

1. **Auth without authz**: PERMISSIVE auth paths (authentication exists, authorization doesn't)
2. **Permissive defaults**: 2+ security-critical fields defaulting to permissive values
3. **Dropped errors on auth path**: errors created and silently dropped in auth-related functions
4. **Orphaned resources**: K8s resources created without ownership or cleanup

Contradictions are sorted by severity (HIGH > MEDIUM > LOW) then by title, and assigned stable sequential IDs.
