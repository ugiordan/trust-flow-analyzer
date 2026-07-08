package rbacscope

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// skipDirs mirrors the loader's skip set so the walk stays consistent.
var skipDirs = map[string]bool{
	".git":         true,
	"__pycache__":  true,
	"node_modules": true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"vendor":       true,
	".tox":         true,
	"dist":         true,
	"build":        true,
	"public":       true,
	"static":       true,
	".next":        true,
	"coverage":     true,
}

// Pass implements the RBAC scope analysis pass.
type Pass struct{}

func (p *Pass) Name() string { return "rbacscope" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.ArchContext != nil && ctx.ArchContext.RBACData != nil {
		return p.runFromArchContext(ctx)
	}
	return p.runSelfExtract(ctx)
}

func (p *Pass) runFromArchContext(ctx *passes.Context) error {
	var findings []types.RBACFinding

	rbac := ctx.ArchContext.RBACData

	for _, role := range rbac.ClusterRoles {
		for _, rule := range role.Rules {
			verbStr := strings.Join(rule.Verbs, ", ")
			resourceStr := strings.Join(rule.Resources, ", ")

			if containsWildcard(rule.Verbs) {
				findings = append(findings, types.RBACFinding{
					Name:     role.Name,
					Kind:     "ClusterRole",
					File:     "arch-context",
					Severity: "HIGH",
					Rule:     fmt.Sprintf("%s [%s]", resourceStr, verbStr),
					Reason:   "ClusterRole grants wildcard verbs (*) at cluster scope. Effectively grants all operations.",
				})
				continue
			}

			if containsWildcard(rule.Resources) {
				findings = append(findings, types.RBACFinding{
					Name:     role.Name,
					Kind:     "ClusterRole",
					File:     "arch-context",
					Severity: "HIGH",
					Rule:     fmt.Sprintf("%s [%s]", resourceStr, verbStr),
					Reason:   "ClusterRole grants access to wildcard resources (*) at cluster scope.",
				})
				continue
			}

			if containsResource(rule.Resources, "secrets") && hasWriteVerbs(rule.Verbs) {
				findings = append(findings, types.RBACFinding{
					Name:     role.Name,
					Kind:     "ClusterRole",
					File:     "arch-context",
					Severity: "HIGH",
					Rule:     fmt.Sprintf("secrets [%s]", verbStr),
					Reason:   "ClusterRole grants secrets CRUD at cluster scope. Namespace-scoped Role preferred.",
				})
			}

			if containsResource(rule.Resources, "configmaps") && hasWriteVerbs(rule.Verbs) {
				findings = append(findings, types.RBACFinding{
					Name:     role.Name,
					Kind:     "ClusterRole",
					File:     "arch-context",
					Severity: "MEDIUM",
					Rule:     fmt.Sprintf("configmaps [%s]", verbStr),
					Reason:   "ClusterRole grants configmaps write access at cluster scope. Consider namespace-scoped Role.",
				})
			}
		}
	}

	for _, binding := range rbac.Bindings {
		if binding.RoleRef == "aggregate-to-edit" {
			findings = append(findings, types.RBACFinding{
				Name:     binding.Name,
				Kind:     "ClusterRoleBinding",
				File:     "arch-context",
				Severity: "MEDIUM",
				Rule:     fmt.Sprintf("roleRef: %s", binding.RoleRef),
				Reason:   "ClusterRoleBinding binds to aggregate-to-edit, which silently expands role permissions via label aggregation.",
			})
		}
	}

	// Consume RBAC-related security annotations from arch-context.
	for _, ann := range ctx.ArchContext.SecurityAnnotations {
		if ann.Type == "RBAC_CLUSTER_SCOPE_SENSITIVE" {
			findings = append(findings, types.RBACFinding{
				Name:     ann.Source,
				Kind:     "ClusterRole",
				File:     "arch-context",
				Severity: ann.Severity,
				Rule:     ann.Type,
				Reason:   ann.Description,
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		si, sj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Name < findings[j].Name
	})

	ctx.Result.RBACFindings = append(ctx.Result.RBACFindings, findings...)
	return nil
}

func (p *Pass) runSelfExtract(ctx *passes.Context) error {
	rootDir := ctx.Program.RootDir

	var findings []types.RBACFinding

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		relPath := relativePath(rootDir, path)
		findings = append(findings, parseYAMLFile(path, relPath)...)
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(findings, func(i, j int) bool {
		si, sj := severityRank(findings[i].Severity), severityRank(findings[j].Severity)
		if si != sj {
			return si < sj
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Name < findings[j].Name
	})

	ctx.Result.RBACFindings = append(ctx.Result.RBACFindings, findings...)
	return nil
}

func parseYAMLFile(path, relPath string) []types.RBACFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []types.RBACFinding

	decoder := yaml.NewDecoder(f)
	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			break
		}
		if doc == nil {
			continue
		}

		kind := getString(doc, "kind")

		switch kind {
		case "ClusterRole":
			findings = append(findings, analyzeClusterRole(doc, relPath)...)
		case "ClusterRoleBinding":
			findings = append(findings, analyzeClusterRoleBinding(doc, relPath)...)
		}
	}

	return findings
}

func analyzeClusterRole(doc map[string]interface{}, relPath string) []types.RBACFinding {
	metadata := getMap(doc, "metadata")
	name := getString(metadata, "name")

	var findings []types.RBACFinding

	rulesRaw, ok := doc["rules"]
	if !ok {
		return findings
	}
	rules, ok := rulesRaw.([]interface{})
	if !ok {
		return findings
	}

	for _, ruleRaw := range rules {
		ruleMap, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}

		resources := getStringSlice(ruleMap, "resources")
		verbs := getStringSlice(ruleMap, "verbs")

		verbStr := strings.Join(verbs, ", ")
		resourceStr := strings.Join(resources, ", ")

		// Check wildcard verbs on any resource.
		if containsWildcard(verbs) {
			findings = append(findings, types.RBACFinding{
				Name:     name,
				Kind:     "ClusterRole",
				File:     relPath,
				Severity: "HIGH",
				Rule:     fmt.Sprintf("%s [%s]", resourceStr, verbStr),
				Reason:   "ClusterRole grants wildcard verbs (*) at cluster scope. Effectively grants all operations.",
			})
			continue
		}

		// Check wildcard resources with any verb.
		if containsWildcard(resources) {
			findings = append(findings, types.RBACFinding{
				Name:     name,
				Kind:     "ClusterRole",
				File:     relPath,
				Severity: "HIGH",
				Rule:     fmt.Sprintf("%s [%s]", resourceStr, verbStr),
				Reason:   "ClusterRole grants access to wildcard resources (*) at cluster scope.",
			})
			continue
		}

		// Check cluster-scoped secrets CRUD.
		if containsResource(resources, "secrets") && hasWriteVerbs(verbs) {
			findings = append(findings, types.RBACFinding{
				Name:     name,
				Kind:     "ClusterRole",
				File:     relPath,
				Severity: "HIGH",
				Rule:     fmt.Sprintf("secrets [%s]", verbStr),
				Reason:   "ClusterRole grants secrets CRUD at cluster scope. Namespace-scoped Role preferred.",
			})
		}

		// Check cluster-scoped configmaps with write verbs.
		if containsResource(resources, "configmaps") && hasWriteVerbs(verbs) {
			findings = append(findings, types.RBACFinding{
				Name:     name,
				Kind:     "ClusterRole",
				File:     relPath,
				Severity: "MEDIUM",
				Rule:     fmt.Sprintf("configmaps [%s]", verbStr),
				Reason:   "ClusterRole grants configmaps write access at cluster scope. Consider namespace-scoped Role.",
			})
		}
	}

	return findings
}

func analyzeClusterRoleBinding(doc map[string]interface{}, relPath string) []types.RBACFinding {
	metadata := getMap(doc, "metadata")
	name := getString(metadata, "name")

	var findings []types.RBACFinding

	roleRef := getMap(doc, "roleRef")
	if roleRef == nil {
		return findings
	}

	roleName := getString(roleRef, "name")

	// Flag bindings to aggregate-to-edit (silently expands roles).
	if roleName == "aggregate-to-edit" {
		findings = append(findings, types.RBACFinding{
			Name:     name,
			Kind:     "ClusterRoleBinding",
			File:     relPath,
			Severity: "MEDIUM",
			Rule:     fmt.Sprintf("roleRef: %s", roleName),
			Reason:   "ClusterRoleBinding binds to aggregate-to-edit, which silently expands role permissions via label aggregation.",
		})
	}

	return findings
}

func containsWildcard(items []string) bool {
	for _, item := range items {
		if item == "*" {
			return true
		}
	}
	return false
}

func containsResource(resources []string, target string) bool {
	for _, r := range resources {
		if r == target {
			return true
		}
	}
	return false
}

// hasWriteVerbs returns true if the verb list includes any write operation.
func hasWriteVerbs(verbs []string) bool {
	writeVerbs := map[string]bool{
		"create": true,
		"update": true,
		"patch":  true,
		"delete": true,
		"*":      true,
	}
	for _, v := range verbs {
		if writeVerbs[v] {
			return true
		}
	}
	return false
}

func getStringSlice(m map[string]interface{}, key string) []string {
	raw, ok := m[key]
	if !ok {
		return nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil
	}
	var result []string
	for _, item := range items {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func severityRank(s string) int {
	switch s {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	case "LOW":
		return 2
	default:
		return 3
	}
}

// Helper functions for safe map access.

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	if m == nil {
		return nil
	}
	if v, ok := m[key]; ok {
		if result, ok := v.(map[string]interface{}); ok {
			return result
		}
	}
	return nil
}

func getString(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func relativePath(rootDir, filePath string) string {
	if rootDir == "" {
		return filePath
	}
	rel, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return filePath
	}
	return rel
}
