package types

// Location identifies a specific point in the source code.
type Location struct {
	File     string
	Line     int
	Column   int
	Function string
	Package  string
}

// AuthFlow represents a distinct authentication/authorization code path.
type AuthFlow struct {
	Name           string
	Entry          Location
	Authentication *AuthStep
	Authorization  *AuthStep
	Sessions       []Location
	Validators     []ValidatorInfo
	Posture        string // PERMISSIVE, RESTRICTIVE, UNKNOWN
}

// AuthStep represents an authentication or authorization checkpoint.
type AuthStep struct {
	Location Location
	Config   []ConfigField
}

// ValidatorInfo describes a validation checkpoint within an auth flow.
type ValidatorInfo struct {
	Location Location
	Kind     string // email, group, role, domain
	Config   []ConfigField
}

// ConfigField captures a configuration value and its security meaning.
type ConfigField struct {
	Name            string
	Value           string
	IsDefault       bool
	PlatformMeaning string
}

// DefaultValue captures a configuration default and what it means at each level.
type DefaultValue struct {
	Field           string
	Location        Location
	LibraryDefault  string
	OperatorDefault string
	PlatformMeaning string
	Permissiveness  string // PERMISSIVE, RESTRICTIVE, NEUTRAL
}

// Contract captures the implicit contract of an exported function.
type Contract struct {
	Function   Location
	Returns    []ReturnInfo
	Violations []ContractViolation
}

// ReturnInfo describes a single return value of a function.
type ReturnInfo struct {
	Index    int
	Type     string
	IsError  bool
	CanBeNil bool
}

// ContractViolation represents a caller that violates a function's implicit contract.
type ContractViolation struct {
	Caller      Location
	Description string
	Kind        string // UNCHECKED_ERROR, NIL_DEREF, CONTEXT_IGNORED
}

// ErrorPath traces an error value from creation to handling.
type ErrorPath struct {
	Origin   Location
	Handlers []ErrorHandler
	Dropped  bool
	FailMode string // OPEN, CLOSED, UNKNOWN
}

// ErrorHandler describes how an error is handled at a specific point.
type ErrorHandler struct {
	Location Location
	Kind     string // LOG, RETURN, WRAP, DROP
}

// ResourceLifecycle traces a Kubernetes resource from creation to cleanup.
type ResourceLifecycle struct {
	Resource   string
	Create     *Location
	Delete     *Location
	Owner      *Location
	Finalizer  *Location
	Orphanable bool
}

// Contradiction captures a cross-file assumption that contradicts reality.
type Contradiction struct {
	ID          string
	Title       string
	Assumptions []Assumption
	Reality     string
	Severity    string // HIGH, MEDIUM, LOW
	Mitigation  string
}

// Assumption represents a single component's assumption about its environment.
type Assumption struct {
	Location    Location
	Description string
}

// SecretExposure captures a pattern where secrets may be exposed through
// insecure mechanisms (e.g. environment variables expanded into process args).
type SecretExposure struct {
	Location    Location
	Pattern     string // ENV_IN_ARGS, HARDCODED_SECRET
	Description string
	Field       string
}

// AuthPolicyInfo describes an authentication/authorization policy resource
// extracted from Kubernetes YAML manifests or Rego policy files.
type AuthPolicyInfo struct {
	Name      string
	Kind      string // AuthPolicy, AuthConfig, AuthorizationPolicy, RegoPolicy
	File      string
	TargetRef string
	Rules     []AuthRule
	SkipPaths []string
}

// AuthRule describes a single rule within an auth policy.
type AuthRule struct {
	Name     string
	Kind     string // authentication, authorization, metadata
	Priority int
}

// RouteCoverage maps a route (HTTPRoute or Ingress) to its covering auth policy.
type RouteCoverage struct {
	Route     string
	RouteFile string
	RouteKind string // HTTPRoute, Ingress
	Policy    string // covering policy name, or "NONE"
	Covered   bool
	Mechanism string // direct, fallback, gateway-default, INTENTIONAL
	Backend   string
}

// NetworkPolicyInfo describes a Kubernetes NetworkPolicy resource.
type NetworkPolicyInfo struct {
	Name        string
	File        string
	Namespace   string
	PodSelector string   // label selector as string
	PolicyTypes []string // Ingress, Egress
	IngressFrom []string // summarized ingress sources
	EgressTo    []string // summarized egress destinations
}

// RBACFinding describes an overprivileged RBAC pattern in a ClusterRole or ClusterRoleBinding.
type RBACFinding struct {
	Name     string
	Kind     string // ClusterRole, ClusterRoleBinding
	File     string
	Severity string // HIGH, MEDIUM, LOW
	Rule     string // which rule is overprivileged
	Reason   string // why it's flagged
}

// MeshPolicyInfo describes a service mesh policy resource (Istio PeerAuthentication, DestinationRule, etc).
type MeshPolicyInfo struct {
	Name      string
	Kind      string // PeerAuthentication, DestinationRule, ServiceMeshMemberRoll, ServiceMeshControlPlane
	File      string
	Namespace string
	MTLSMode  string // STRICT, PERMISSIVE, DISABLE, UNSET
	Scope     string // namespace-wide, workload-specific, mesh-wide
}

// AnalysisResult holds the combined output of all analysis passes.
type AnalysisResult struct {
	Project          string
	AuthFlows        []AuthFlow
	Defaults         []DefaultValue
	Contracts        []Contract
	ErrorPaths       []ErrorPath
	Lifecycles       []ResourceLifecycle
	SecretExposures  []SecretExposure
	AuthPolicies     []AuthPolicyInfo
	RouteCoverage    []RouteCoverage
	NetworkPolicies  []NetworkPolicyInfo
	RBACFindings     []RBACFinding
	MeshPolicies     []MeshPolicyInfo
	Contradictions   []Contradiction
}
