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
	Create     Location
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

// AnalysisResult holds the combined output of all analysis passes.
type AnalysisResult struct {
	Project        string
	AuthFlows      []AuthFlow
	Defaults       []DefaultValue
	Contracts      []Contract
	ErrorPaths     []ErrorPath
	Lifecycles     []ResourceLifecycle
	Contradictions []Contradiction
}
