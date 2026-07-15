package netpolicy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass implements the NetworkPolicy analysis pass.
type Pass struct{}

func (p *Pass) Name() string { return "netpolicy" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.ArchContext != nil && len(ctx.ArchContext.NetworkPolicies) > 0 {
		return p.runFromArchContext(ctx)
	}
	return p.runSelfExtract(ctx)
}

func (p *Pass) runFromArchContext(ctx *passes.Context) error {
	var policies []types.NetworkPolicyInfo

	for _, np := range ctx.ArchContext.NetworkPolicies {
		policies = append(policies, types.NetworkPolicyInfo{
			Name:        np.Name,
			File:        "arch-context",
			Namespace:   np.Namespace,
			PodSelector: np.PodSelector,
			PolicyTypes: np.PolicyTypes,
		})
	}

	sort.Slice(policies, func(i, j int) bool {
		if policies[i].File != policies[j].File {
			return policies[i].File < policies[j].File
		}
		return policies[i].Name < policies[j].Name
	})

	ctx.Result.NetworkPolicies = append(ctx.Result.NetworkPolicies, policies...)
	return nil
}

func (p *Pass) runSelfExtract(ctx *passes.Context) error {
	rootDir := ctx.Program.RootDir

	var policies []types.NetworkPolicyInfo

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if loader.ShouldSkipDir(info.Name()) {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}

		relPath := relativePath(rootDir, path)
		policies = append(policies, parseYAMLFile(path, relPath)...)
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(policies, func(i, j int) bool {
		if policies[i].File != policies[j].File {
			return policies[i].File < policies[j].File
		}
		return policies[i].Name < policies[j].Name
	})

	ctx.Result.NetworkPolicies = append(ctx.Result.NetworkPolicies, policies...)
	return nil
}

func parseYAMLFile(path, relPath string) []types.NetworkPolicyInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var policies []types.NetworkPolicyInfo

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
		if kind != "NetworkPolicy" {
			continue
		}

		policies = append(policies, extractNetworkPolicy(doc, relPath))
	}

	return policies
}

func extractNetworkPolicy(doc map[string]interface{}, relPath string) types.NetworkPolicyInfo {
	metadata := getMap(doc, "metadata")
	spec := getMap(doc, "spec")

	name := getString(metadata, "name")
	namespace := getString(metadata, "namespace")

	podSelector := formatSelector(getMap(spec, "podSelector"))

	var policyTypes []string
	if ptRaw, ok := spec["policyTypes"]; ok {
		if items, ok := ptRaw.([]interface{}); ok {
			for _, item := range items {
				if s, ok := item.(string); ok {
					policyTypes = append(policyTypes, s)
				}
			}
		}
	}

	var ingressFrom []string
	if ingressRaw, ok := spec["ingress"]; ok {
		if rules, ok := ingressRaw.([]interface{}); ok {
			for _, rule := range rules {
				ruleMap, ok := rule.(map[string]interface{})
				if !ok {
					continue
				}
				ingressFrom = append(ingressFrom, extractIngressSources(ruleMap)...)
			}
		}
	}

	var egressTo []string
	if egressRaw, ok := spec["egress"]; ok {
		if rules, ok := egressRaw.([]interface{}); ok {
			for _, rule := range rules {
				ruleMap, ok := rule.(map[string]interface{})
				if !ok {
					continue
				}
				egressTo = append(egressTo, extractEgressDestinations(ruleMap)...)
			}
		}
	}

	return types.NetworkPolicyInfo{
		Name:        name,
		File:        relPath,
		Namespace:   namespace,
		PodSelector: podSelector,
		PolicyTypes: policyTypes,
		IngressFrom: ingressFrom,
		EgressTo:    egressTo,
	}
}

func extractIngressSources(rule map[string]interface{}) []string {
	var sources []string
	fromRaw, ok := rule["from"]
	if !ok {
		return sources
	}
	items, ok := fromRaw.([]interface{})
	if !ok {
		return sources
	}

	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		if nsSelector := getMap(m, "namespaceSelector"); nsSelector != nil {
			labels := formatMatchLabels(nsSelector)
			if podSel := getMap(m, "podSelector"); podSel != nil {
				podLabels := formatMatchLabels(podSel)
				sources = append(sources, fmt.Sprintf("namespace: %s, pod: %s", labels, podLabels))
			} else {
				sources = append(sources, fmt.Sprintf("namespace: %s", labels))
			}
		} else if podSel := getMap(m, "podSelector"); podSel != nil {
			labels := formatMatchLabels(podSel)
			sources = append(sources, fmt.Sprintf("pod: %s", labels))
		}

		if ipBlock := getMap(m, "ipBlock"); ipBlock != nil {
			cidr := getString(ipBlock, "cidr")
			if cidr != "" {
				sources = append(sources, fmt.Sprintf("ipBlock: %s", cidr))
			}
		}
	}

	return sources
}

func extractEgressDestinations(rule map[string]interface{}) []string {
	var destinations []string
	toRaw, ok := rule["to"]
	if !ok {
		return destinations
	}
	items, ok := toRaw.([]interface{})
	if !ok {
		return destinations
	}

	for _, item := range items {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		if nsSelector := getMap(m, "namespaceSelector"); nsSelector != nil {
			labels := formatMatchLabels(nsSelector)
			if podSel := getMap(m, "podSelector"); podSel != nil {
				podLabels := formatMatchLabels(podSel)
				destinations = append(destinations, fmt.Sprintf("namespace: %s, pod: %s", labels, podLabels))
			} else {
				destinations = append(destinations, fmt.Sprintf("namespace: %s", labels))
			}
		} else if podSel := getMap(m, "podSelector"); podSel != nil {
			labels := formatMatchLabels(podSel)
			destinations = append(destinations, fmt.Sprintf("pod: %s", labels))
		}

		if ipBlock := getMap(m, "ipBlock"); ipBlock != nil {
			cidr := getString(ipBlock, "cidr")
			if cidr != "" {
				destinations = append(destinations, fmt.Sprintf("ipBlock: %s", cidr))
			}
		}
	}

	return destinations
}

// formatSelector converts a podSelector map into a human-readable label string.
func formatSelector(selector map[string]interface{}) string {
	if selector == nil {
		return "(all pods)"
	}
	labels := formatMatchLabels(selector)
	if labels == "" {
		return "(all pods)"
	}
	return labels
}

// formatMatchLabels extracts matchLabels from a selector and formats them as key=value pairs.
func formatMatchLabels(selector map[string]interface{}) string {
	ml := getMap(selector, "matchLabels")
	if ml == nil {
		return ""
	}

	var parts []string
	for k, v := range ml {
		if s, ok := v.(string); ok {
			parts = append(parts, fmt.Sprintf("%s=%s", k, s))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
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
