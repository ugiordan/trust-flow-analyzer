package passes

import (
	"github.com/ugiordan/trust-flow-analyzer/pkg/config"
	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// ArchComponent represents a component from an architecture-analyzer output.
type ArchComponent struct {
	Name     string   `json:"name"`
	Packages []string `json:"packages"`
}

// ArchRBACData holds RBAC information extracted by the architecture-analyzer.
type ArchRBACData struct {
	ClusterRoles []ArchRBACRole    `json:"cluster_roles"`
	Roles        []ArchRBACRole    `json:"roles"`
	Bindings     []ArchRBACBinding `json:"cluster_role_bindings"`
}

// ArchRBACRole represents a ClusterRole or Role with its rules.
type ArchRBACRole struct {
	Name  string         `json:"name"`
	Rules []ArchRBACRule `json:"rules"`
}

// ArchRBACRule represents a single RBAC policy rule.
type ArchRBACRule struct {
	APIGroups []string `json:"api_groups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// ArchRBACBinding represents a ClusterRoleBinding.
type ArchRBACBinding struct {
	Name    string `json:"name"`
	RoleRef string `json:"role_ref"`
}

// ArchNetworkPolicy represents a NetworkPolicy from architecture-analyzer output.
type ArchNetworkPolicy struct {
	Name        string   `json:"name"`
	Namespace   string   `json:"namespace"`
	PodSelector string   `json:"pod_selector"`
	PolicyTypes []string `json:"policy_types"`
}

// ArchSecurityFinding represents a security finding from architecture-analyzer output.
type ArchSecurityFinding struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Source      string `json:"source"`
	Description string `json:"description"`
}

// ArchDeployment represents a deployment from architecture-analyzer output.
type ArchDeployment struct {
	Name       string   `json:"name"`
	Containers []string `json:"containers"`
	Sidecars   []string `json:"sidecars"`
}

// ArchContext holds parsed architecture context from an external analyzer.
type ArchContext struct {
	Components          []ArchComponent       `json:"components"`
	RBACData            *ArchRBACData         `json:"rbac"`
	NetworkPolicies     []ArchNetworkPolicy   `json:"network_policies"`
	SecurityAnnotations []ArchSecurityFinding  `json:"security_annotations"`
	Deployments         []ArchDeployment      `json:"deployments"`
}

// Context holds shared state for all analysis passes.
type Context struct {
	Program      *ir.AnalysisProgram
	Platform     *platform.Knowledge
	Result       *types.AnalysisResult
	ArchContext  *ArchContext
	CustomConfig *config.Config // optional user-provided custom rules
}

// Pass is the interface that all analysis passes implement.
type Pass interface {
	Name() string
	Run(ctx *Context) error
}
