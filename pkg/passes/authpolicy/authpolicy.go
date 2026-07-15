package authpolicy

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// supportedKinds lists the K8s resource kinds this pass recognises as auth-related.
var supportedKinds = map[string]bool{
	"AuthPolicy":          true,
	"AuthConfig":          true,
	"AuthorizationPolicy": true,
}

// healthPatterns matches common health/readiness paths that are intentionally
// left unauthenticated.
var healthPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^/health`),
	regexp.MustCompile(`(?i)^/ready`),
	regexp.MustCompile(`(?i)^/live`),
	regexp.MustCompile(`(?i)^/readyz`),
	regexp.MustCompile(`(?i)^/healthz`),
	regexp.MustCompile(`(?i)^/livez`),
}

// Pass implements the auth-policy analysis pass.
type Pass struct{}

func (p *Pass) Name() string { return "authpolicy" }

func (p *Pass) Run(ctx *passes.Context) error {
	rootDir := ctx.Program.RootDir

	var policies []types.AuthPolicyInfo
	var routes []routeInfo
	var gateways []gatewayInfo

	// Walk all YAML files.
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip inaccessible paths
		}
		if info.IsDir() {
			if loader.ShouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		relPath := relativePath(rootDir, path)

		switch ext {
		case ".yaml", ".yml":
			p, r, g := parseYAMLFile(path, relPath)
			policies = append(policies, p...)
			routes = append(routes, r...)
			gateways = append(gateways, g...)
		case ".rego":
			if pol := parseRegoFile(path, relPath); pol != nil {
				policies = append(policies, *pol)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Build route-to-policy coverage.
	coverage := buildCoverage(policies, routes, gateways)

	// Sort for deterministic output.
	sort.Slice(policies, func(i, j int) bool {
		if policies[i].File != policies[j].File {
			return policies[i].File < policies[j].File
		}
		return policies[i].Name < policies[j].Name
	})
	sort.Slice(coverage, func(i, j int) bool {
		if coverage[i].RouteFile != coverage[j].RouteFile {
			return coverage[i].RouteFile < coverage[j].RouteFile
		}
		return coverage[i].Route < coverage[j].Route
	})

	ctx.Result.AuthPolicies = append(ctx.Result.AuthPolicies, policies...)
	ctx.Result.RouteCoverage = append(ctx.Result.RouteCoverage, coverage...)

	return nil
}

// routeInfo is an intermediate structure for parsed routes.
type routeInfo struct {
	Name       string
	File       string
	Kind       string // HTTPRoute, Ingress
	ParentRefs []string
	Paths      []routePath
}

type routePath struct {
	Path    string
	Backend string
}

// gatewayInfo tracks Gateway resources for default-policy detection.
type gatewayInfo struct {
	Name string
	File string
}

// parseYAMLFile reads a YAML file, splitting on multi-document separators,
// and returns any auth policies, routes, and gateways found.
func parseYAMLFile(path, relPath string) ([]types.AuthPolicyInfo, []routeInfo, []gatewayInfo) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil
	}
	defer f.Close()

	var policies []types.AuthPolicyInfo
	var routes []routeInfo
	var gateways []gatewayInfo

	decoder := yaml.NewDecoder(f)
	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			// Skip malformed documents.
			break
		}
		if doc == nil {
			continue
		}

		kind := getString(doc, "kind")

		switch {
		case supportedKinds[kind]:
			policies = append(policies, extractPolicy(doc, kind, relPath))
		case kind == "HTTPRoute":
			routes = append(routes, extractHTTPRoute(doc, relPath))
		case kind == "Ingress":
			routes = append(routes, extractIngress(doc, relPath))
		case kind == "Gateway":
			gateways = append(gateways, extractGateway(doc, relPath))
		}
	}

	return policies, routes, gateways
}

// extractPolicy pulls auth policy details from a parsed YAML document.
func extractPolicy(doc map[string]interface{}, kind, relPath string) types.AuthPolicyInfo {
	metadata := getMap(doc, "metadata")
	spec := getMap(doc, "spec")

	name := getString(metadata, "name")
	targetRef := ""
	if tr := getMap(spec, "targetRef"); tr != nil {
		trKind := getString(tr, "kind")
		trName := getString(tr, "name")
		if trKind != "" || trName != "" {
			targetRef = trKind + "/" + trName
		}
	}

	var rules []types.AuthRule
	var skipPaths []string

	// Extract rules from spec.rules (Kuadrant AuthPolicy style).
	if rulesMap := getMap(spec, "rules"); rulesMap != nil {
		for ruleKind, v := range rulesMap {
			innerMap, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			for ruleName, rv := range innerMap {
				priority := 0
				if ruleMap, ok := rv.(map[string]interface{}); ok {
					if p, ok := ruleMap["priority"]; ok {
						priority = toInt(p)
					}
				}
				rules = append(rules, types.AuthRule{
					Name:     ruleName,
					Kind:     ruleKind,
					Priority: priority,
				})
			}
		}
	}

	// Extract skip paths from spec.when predicates.
	if whenList, ok := spec["when"]; ok {
		if items, ok := whenList.([]interface{}); ok {
			for _, item := range items {
				if m, ok := item.(map[string]interface{}); ok {
					pred := getString(m, "predicate")
					if pred != "" {
						skipPaths = append(skipPaths, extractSkipPaths(pred)...)
					}
				}
			}
		}
	}

	// Sort rules for deterministic output.
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Kind != rules[j].Kind {
			return rules[i].Kind < rules[j].Kind
		}
		return rules[i].Name < rules[j].Name
	})

	return types.AuthPolicyInfo{
		Name:      name,
		Kind:      kind,
		File:      relPath,
		TargetRef: targetRef,
		Rules:     rules,
		SkipPaths: skipPaths,
	}
}

// extractSkipPaths parses predicate strings for path exclusions.
// Handles patterns like: request.path != "/health"
func extractSkipPaths(predicate string) []string {
	var paths []string
	// Match request.path != "/some/path" or request.path != '/some/path'
	re := regexp.MustCompile(`request\.path\s*!=\s*["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(predicate, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			paths = append(paths, m[1])
		}
	}
	return paths
}

func extractHTTPRoute(doc map[string]interface{}, relPath string) routeInfo {
	metadata := getMap(doc, "metadata")
	spec := getMap(doc, "spec")

	name := getString(metadata, "name")

	var parentRefs []string
	if prs, ok := spec["parentRefs"]; ok {
		if items, ok := prs.([]interface{}); ok {
			for _, item := range items {
				if m, ok := item.(map[string]interface{}); ok {
					parentRefs = append(parentRefs, getString(m, "name"))
				}
			}
		}
	}

	var paths []routePath
	if rulesRaw, ok := spec["rules"]; ok {
		if items, ok := rulesRaw.([]interface{}); ok {
			for _, item := range items {
				ruleMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				// Extract paths from matches.
				if matchesRaw, ok := ruleMap["matches"]; ok {
					if matchItems, ok := matchesRaw.([]interface{}); ok {
						for _, mi := range matchItems {
							if mm, ok := mi.(map[string]interface{}); ok {
								if pathMap := getMap(mm, "path"); pathMap != nil {
									pathVal := getString(pathMap, "value")
									if pathVal != "" {
										backend := extractBackendName(ruleMap)
										paths = append(paths, routePath{
											Path:    pathVal,
											Backend: backend,
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return routeInfo{
		Name:       name,
		File:       relPath,
		Kind:       "HTTPRoute",
		ParentRefs: parentRefs,
		Paths:      paths,
	}
}

func extractIngress(doc map[string]interface{}, relPath string) routeInfo {
	metadata := getMap(doc, "metadata")
	spec := getMap(doc, "spec")

	name := getString(metadata, "name")

	var paths []routePath
	if rulesRaw, ok := spec["rules"]; ok {
		if items, ok := rulesRaw.([]interface{}); ok {
			for _, item := range items {
				ruleMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if httpMap := getMap(ruleMap, "http"); httpMap != nil {
					if pathsRaw, ok := httpMap["paths"]; ok {
						if pathItems, ok := pathsRaw.([]interface{}); ok {
							for _, pi := range pathItems {
								if pm, ok := pi.(map[string]interface{}); ok {
									pathVal := getString(pm, "path")
									if pathVal != "" {
										backend := ""
										if backendMap := getMap(pm, "backend"); backendMap != nil {
											if svc := getMap(backendMap, "service"); svc != nil {
												backend = getString(svc, "name")
											}
										}
										paths = append(paths, routePath{
											Path:    pathVal,
											Backend: backend,
										})
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return routeInfo{
		Name:       name,
		File:       relPath,
		Kind:       "Ingress",
		ParentRefs: nil,
		Paths:      paths,
	}
}

func extractGateway(doc map[string]interface{}, relPath string) gatewayInfo {
	metadata := getMap(doc, "metadata")
	return gatewayInfo{
		Name: getString(metadata, "name"),
		File: relPath,
	}
}

func extractBackendName(ruleMap map[string]interface{}) string {
	if brRaw, ok := ruleMap["backendRefs"]; ok {
		if items, ok := brRaw.([]interface{}); ok {
			if len(items) > 0 {
				if m, ok := items[0].(map[string]interface{}); ok {
					return getString(m, "name")
				}
			}
		}
	}
	return ""
}

// buildCoverage maps routes to policies by matching targetRef names.
func buildCoverage(policies []types.AuthPolicyInfo, routes []routeInfo, gateways []gatewayInfo) []types.RouteCoverage {
	// Build policy lookup by targetRef.
	// Key: "Kind/Name" (e.g. "HTTPRoute/api-route")
	policyByTarget := make(map[string]types.AuthPolicyInfo)
	// Policies targeting gateways act as defaults.
	var gatewayPolicies []types.AuthPolicyInfo

	for _, pol := range policies {
		if pol.TargetRef != "" {
			policyByTarget[pol.TargetRef] = pol
			if strings.HasPrefix(pol.TargetRef, "Gateway/") {
				gatewayPolicies = append(gatewayPolicies, pol)
			}
		}
	}

	// Build gateway name set for matching.
	gatewayNames := make(map[string]bool)
	for _, gw := range gateways {
		gatewayNames[gw.Name] = true
	}

	var coverage []types.RouteCoverage

	for _, route := range routes {
		// Check direct policy match.
		targetKey := route.Kind + "/" + route.Name
		directPolicy, hasDirect := policyByTarget[targetKey]

		// Check if any parent gateway has a default policy.
		var gwPolicy *types.AuthPolicyInfo
		for _, parentName := range route.ParentRefs {
			gwKey := "Gateway/" + parentName
			if gp, ok := policyByTarget[gwKey]; ok {
				gwPolicy = &gp
				break
			}
		}

		for _, rp := range route.Paths {
			cov := types.RouteCoverage{
				Route:     rp.Path,
				RouteFile: route.File,
				RouteKind: route.Kind,
				Backend:   rp.Backend,
			}

			// Check if this path is a health/readiness endpoint.
			if isHealthPath(rp.Path) {
				cov.Covered = true
				cov.Policy = "(health endpoint)"
				cov.Mechanism = "INTENTIONAL"
				coverage = append(coverage, cov)
				continue
			}

			// Check if this path is in a policy's skip list.
			if hasDirect {
				for _, sp := range directPolicy.SkipPaths {
					if sp == rp.Path || strings.HasPrefix(rp.Path, sp) {
						cov.Covered = true
						cov.Policy = directPolicy.Name
						cov.Mechanism = "INTENTIONAL"
						break
					}
				}
				if cov.Mechanism == "INTENTIONAL" {
					coverage = append(coverage, cov)
					continue
				}
			}

			if hasDirect {
				cov.Covered = true
				cov.Policy = directPolicy.Name
				cov.Mechanism = "direct"
			} else if gwPolicy != nil {
				cov.Covered = true
				cov.Policy = gwPolicy.Name
				cov.Mechanism = "gateway-default"
			} else {
				cov.Covered = false
				cov.Policy = "NONE"
				cov.Mechanism = ""
			}

			coverage = append(coverage, cov)
		}
	}

	return coverage
}

func isHealthPath(path string) bool {
	for _, re := range healthPatterns {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}

// parseRegoFile scans a .rego file for policy rules.
func parseRegoFile(path, relPath string) *types.AuthPolicyInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var packageName string
	var rules []types.AuthRule

	authRulePattern := regexp.MustCompile(`(?i)\b(allow|deny|authz)\b`)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "package ") {
			packageName = strings.TrimPrefix(line, "package ")
			continue
		}

		// Look for rule definitions: "ruleName { ... }" or "ruleName = ... {"
		// Also handles "default allow = false"
		if strings.HasPrefix(line, "default ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 && authRulePattern.MatchString(parts[1]) {
				rules = append(rules, types.AuthRule{
					Name: parts[1],
					Kind: "authorization",
				})
			}
			continue
		}

		// Match rule heads: "allow { ...", "allow if { ...", "deny[msg] { ..."
		if idx := strings.IndexAny(line, " {["); idx > 0 {
			ruleName := line[:idx]
			if authRulePattern.MatchString(ruleName) {
				// Avoid duplicates.
				found := false
				for _, r := range rules {
					if r.Name == ruleName {
						found = true
						break
					}
				}
				if !found {
					rules = append(rules, types.AuthRule{
						Name: ruleName,
						Kind: "authorization",
					})
				}
			}
		}
	}

	if len(rules) == 0 {
		return nil
	}

	name := packageName
	if name == "" {
		name = filepath.Base(path)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Name < rules[j].Name
	})

	return &types.AuthPolicyInfo{
		Name:  name,
		Kind:  "RegoPolicy",
		File:  relPath,
		Rules: rules,
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

func toInt(v interface{}) int {
	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	}
	return 0
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
