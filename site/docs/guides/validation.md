# Validation on Real Projects

trust-flow-analyzer was validated against production Kubernetes projects from the OpenShift AI ecosystem. Each exercises different parts of the analysis: HTTP auth flows, operator configuration defaults, controller resource lifecycle, auth policy coverage, and multi-language support.

## Results Summary

| Target | Language | Auth Flows | Config Defaults | Contracts | Error Paths | Lifecycles | Auth Policies | Route Coverage | Network Policies | RBAC | mTLS | Template Risks | Webhook Defaults | Contradictions |
|--------|----------|-----------|----------------|-----------|-------------|------------|---------------|----------------|-----------------|------|------|----------------|-----------------|----------------|
| [kube-auth-proxy](https://github.com/opendatahub-io/kube-auth-proxy) | Go | 3 | 5 | 3 | 275 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 2 |
| [opendatahub-operator](https://github.com/opendatahub-io/opendatahub-operator) | Go | 0 | 38 | 0 | 0 | 0 | 4 | 8 | 3 | 5 | 2 | 6 | 2 | 8 |
| [kserve](https://github.com/kserve/kserve) | Go | 0 | 58 | 4 | 746 | 31 | 2 | 5 | 1 | 3 | 1 | 4 | 3 | 16 |
| [model-registry-operator](https://github.com/opendatahub-io/model-registry-operator) | Go | 0 | 12 | 1 | 42 | 4 | 1 | 2 | 1 | 2 | 0 | 3 | 1 | 5 |
| [odh-dashboard](https://github.com/opendatahub-io/odh-dashboard) | TypeScript | 0 | 3 | 0 | 18 | 0 | 0 | 0 | 0 | 0 | 0 | 2 | 0 | 1 |

## kube-auth-proxy: auth flow separation

This is the primary validation target. kube-auth-proxy is a fork of oauth2-proxy that adds Kubernetes authentication (TokenReview) and is deployed as a sidecar in RHOAI.

The tool correctly identifies **3 distinct auth entry points**, all sharing the same authentication chain:

```
### Path: v1.OAuthProxy
Entry: oauthproxy.go:ServeHTTP (line 574)
Authentication: oauthproxy.go:getAuthenticatedSession (line 1304)
Session: oidc.go:CreateSessionFromToken (line 198)
Session: openshift.go:CreateSessionFromToken (line 320)
Authorization: oauthproxy.go:IsAllowedRequest (line 624)
Validator (authn): tokenreview.go:ValidateToken (line 78)
Validator (authz): provider_default.go:Authorize (line 124)
Validator (email): validator.go:isEmailValidWithDomains (line 112)
Combined posture: RESTRICTIVE
```

### Configuration defaults detected

The tool found 5 security-critical fields with permissive defaults:

| Field | Default | Platform Meaning |
|-------|---------|-----------------|
| `email-domain` | `[]` (empty) | Accept any email domain |
| `OIDCOptions.InsecureSkipNonce` | `true` | OIDC replay protection disabled |
| `Provider.AllowedGroups` | `<complex>` | Authorize all authenticated users |
| `TokenReviewValidator.audiences` | `audiences` | Accept API server audience (all pods) |

### Contradiction: triple permissive default

```
CONTRADICTION-001: Multiple security-critical fields default to permissive values
- options.go (line 151): email-domain defaults to [] (Accept any email domain)
- legacy_options.go (line 680): AllowedGroups defaults to <complex> (Authorize all)
- tokenreview.go (line 68): audiences defaults to audiences (Accept all pods)
Combined: 3 configuration fields default to permissive values.
Severity: MEDIUM
```

This is exactly the finding that motivated building the tool: three separate files each set a permissive default, and their combined effect creates an open access path. No single-file analysis would flag this.

### Contract violations

```
oauthproxy.go:SignOut does not check error from getAuthenticatedSession
```

The `SignOut` handler calls `getAuthenticatedSession` but ignores its error return, meaning a failed session lookup during sign-out could lead to unexpected behavior.

## opendatahub-operator: models-as-a-service validation

The operator manages the deployment of AI platform components. The new auth policy and config-level passes surface significant findings.

### AuthPolicy detection and route coverage

The tool detected **4 auth policies** (Authorino AuthConfig resources) and mapped them against **8 routes**. Key finding: not all HTTPRoute resources have a matching auth policy, surfacing coverage gaps in the models-as-a-service deployment.

### Configuration defaults

The tool found **38 configuration defaults**, including the auth proxy sidecar fields:

- `AuthSpec.AllowedGroups`: controls which groups can access managed components
- `KubeRBACProxy`: nil means no kube-rbac-proxy sidecar deployed
- `OAuthProxy`: nil means no OAuth proxy sidecar deployed
- `Authorino`: nil means no Authorino auth policy applied
- `MonitoringCommonSpec.Namespace`: monitoring namespace scope

### Webhook defaults

The operator has webhook defaulter methods that set some security fields but leave others unset. The tool surfaces which fields each `Default()` method covers and which it skips.

### Template risks

6 template risks detected across kustomize overlays and deployment templates, including secrets expanded in container args and conditional security sidecar injection.

### Contradictions

8 contradictions detected, including permissive auth defaults, uncovered routes, and template-based secret exposure.

## model-registry-operator: params.env detection

The model-registry-operator uses `params.env` files in its kustomize overlays. The DefaultValue pass detects these and flags security-relevant keys that are empty or unset.

### params.env findings

The tool found params.env files in kustomize overlay directories and detected empty security-relevant configuration keys (database passwords, TLS settings). These appear as configuration defaults with `(empty) params.env (kustomize)` as the operator default.

### Webhook defaults

The `ModelRegistry.Default` webhook method was analyzed. The tool reports which security fields (sslMode, auth proxy sidecars) the defaulter sets and which it does not.

## kserve: resource lifecycle tracking

kserve is a model serving platform that manages many Kubernetes resources. The tool detected **31 resource types** being created or managed:

ConfigMap, Deployment, Gateway, GatewayClass, HTTPRoute, HorizontalPodAutoscaler, InferenceGraph, InferenceService, Ingress, Job, LLMInferenceService, LocalModelCache, Namespace, PersistentVolume, PersistentVolumeClaim, Route, ScaledObject, Service, ServiceAccount, VirtualService, and more.

### Contradictions: orphanable resources

16 contradictions were detected, including 10 resources created without owner references or finalizers:

```
CONTRADICTION-002: ConfigMap created without ownership or cleanup
CONTRADICTION-003: Gateway created without ownership or cleanup
CONTRADICTION-007: PersistentVolume created without ownership or cleanup
CONTRADICTION-008: PersistentVolumeClaim created without ownership or cleanup
CONTRADICTION-009: ServiceAccount created without ownership or cleanup
```

These are resources that would be orphaned if their parent is deleted, since there's no automatic garbage collection (no OwnerReference) or manual cleanup (no finalizer, no explicit delete).

Additional contradictions cover auth policy gaps, overprivileged RBAC, and template risks in the kserve deployment manifests.

!!! note "Not all orphanable resources are bugs"
    Some resources are intentionally created without ownership (e.g., Namespace-scoped resources that should outlive their creator). The tool flags them for review, not as definitive bugs.

## odh-dashboard: TypeScript validation

odh-dashboard is a React/TypeScript frontend application. This validates the tree-sitter analysis path for non-Go projects.

### Error propagation

The tool detected **18 error creation points** across the TypeScript codebase, tracking `throw` statements and empty `catch` blocks.

### Template risks

2 template risks detected in configuration templates used for backend API proxy setup.

### Contradiction

1 contradiction detected from permissive configuration defaults in the proxy configuration.

This validates that the same 11-pass analysis framework works on TypeScript projects via tree-sitter, though with less call graph precision than Go's SSA+VTA backend.

## Known Limitations

These are analysis gaps identified during validation, planned for future versions.

### No lifecycle detection in opendatahub-operator

The operator uses controller-runtime's `client.Client` extensively but some CRUD operations go through wrapper functions (e.g., `deploy.Apply`, custom action handlers) that add a level of indirection the current SSA analysis can't trace through. The tool detects direct `client.Create`/`client.Delete` calls and single-level interface dispatch, but not multi-hop wrappers.

### Remaining Namespace noise

The K8s API type filter removes `ObjectMeta.Namespace` and similar stdlib assignments, but project-internal structs with a `Namespace` field still match. Some of these are genuine security defaults (controller watch scope), others are just configuration values. The tool currently flags all of them.

### No kube-rbac-proxy path detection

kube-auth-proxy has two auth paths in production: the oauth-proxy path (in this repo) and the kube-rbac-proxy path (a separate binary). The tool correctly maps what's in the analyzed repo but can't see the other process. Cross-repo analysis would require running the tool on both repos and correlating the results.

### Auth flow detection limited to HTTP and webhooks

The tool detects `ServeHTTP`, handler functions, admission webhooks, and controller `Reconcile` methods. gRPC servers, custom TCP listeners, and other non-HTTP entry points are not detected.

### Tree-sitter call graph precision

For Python, TypeScript, and Rust projects, call graph construction is heuristic (name-based resolution). This means indirect calls through higher-order functions, dynamic dispatch, and computed method names may not be resolved. The YAML-scanning passes (AuthPolicy, NetworkPolicy, RBAC, mTLS, Template) work with full precision regardless of language.
