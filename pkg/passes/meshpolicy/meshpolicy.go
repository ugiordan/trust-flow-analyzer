package meshpolicy

import (
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

// supportedKinds lists the K8s resource kinds this pass recognises as mesh-related.
var supportedKinds = map[string]bool{
	"PeerAuthentication":      true,
	"DestinationRule":         true,
	"ServiceMeshMemberRoll":   true,
	"ServiceMeshControlPlane": true,
}

// Pass implements the service mesh / mTLS detection pass.
type Pass struct{}

func (p *Pass) Name() string { return "meshpolicy" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.ArchContext != nil {
		return p.runFromArchContext(ctx)
	}
	return p.runSelfExtract(ctx)
}

func (p *Pass) runFromArchContext(ctx *passes.Context) error {
	// The architecture-analyzer does not currently produce mesh-specific
	// structured data, so we still self-extract mesh policies from YAML.
	// This method is the extension point: when arch-analyzer gains Istio/OSSM
	// extraction, mesh data will be consumed here instead of walking files.
	return p.runSelfExtract(ctx)
}

func (p *Pass) runSelfExtract(ctx *passes.Context) error {
	rootDir := ctx.Program.RootDir

	var policies []types.MeshPolicyInfo

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

	ctx.Result.MeshPolicies = append(ctx.Result.MeshPolicies, policies...)
	return nil
}

func parseYAMLFile(path, relPath string) []types.MeshPolicyInfo {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var policies []types.MeshPolicyInfo

	decoder := yaml.NewDecoder(f)
	for {
		var doc map[string]interface{}
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			// Skip malformed documents and continue to the next one.
			continue
		}
		if doc == nil {
			continue
		}

		kind := getString(doc, "kind")
		if !supportedKinds[kind] {
			continue
		}

		policies = append(policies, extractMeshPolicy(doc, kind, relPath))
	}

	return policies
}

func extractMeshPolicy(doc map[string]interface{}, kind, relPath string) types.MeshPolicyInfo {
	metadata := getMap(doc, "metadata")
	spec := getMap(doc, "spec")

	name := getString(metadata, "name")
	namespace := getString(metadata, "namespace")

	mtlsMode := "UNSET"
	scope := "namespace-wide"

	switch kind {
	case "PeerAuthentication":
		mtlsMode, scope = extractPeerAuth(spec, namespace)
	case "DestinationRule":
		mtlsMode = extractDestinationRuleTLS(spec)
		scope = "workload-specific"
	case "ServiceMeshMemberRoll":
		mtlsMode = "UNSET"
		scope = "mesh-wide"
	case "ServiceMeshControlPlane":
		mtlsMode = extractSMCPMTLS(spec)
		scope = "mesh-wide"
	}

	// Check for sidecar injection annotation.
	if annotations := getMap(metadata, "annotations"); annotations != nil {
		if inject := getString(annotations, "sidecar.istio.io/inject"); inject != "" {
			if inject == "false" {
				mtlsMode = "DISABLE"
				scope = "workload-specific"
			}
		}
	}

	return types.MeshPolicyInfo{
		Name:      name,
		Kind:      kind,
		File:      relPath,
		Namespace: namespace,
		MTLSMode:  mtlsMode,
		Scope:     scope,
	}
}

func extractPeerAuth(spec map[string]interface{}, namespace string) (string, string) {
	if spec == nil {
		return "UNSET", "namespace-wide"
	}

	mode := "UNSET"
	scope := "namespace-wide"

	// Check spec.mtls.mode for namespace-wide or mesh-wide setting.
	if mtls := getMap(spec, "mtls"); mtls != nil {
		if m := getString(mtls, "mode"); m != "" {
			mode = strings.ToUpper(m)
		}
	}

	// Check if there's a selector (workload-specific) or not.
	if selector := getMap(spec, "selector"); selector != nil {
		if ml := getMap(selector, "matchLabels"); ml != nil && len(ml) > 0 {
			scope = "workload-specific"
		}
	}

	// If namespace is istio-system or empty and no selector, it's mesh-wide.
	if scope == "namespace-wide" && (namespace == "istio-system" || namespace == "") {
		scope = "mesh-wide"
	}

	return mode, scope
}

func extractDestinationRuleTLS(spec map[string]interface{}) string {
	if spec == nil {
		return "UNSET"
	}

	// Check spec.trafficPolicy.tls.mode.
	if tp := getMap(spec, "trafficPolicy"); tp != nil {
		if tls := getMap(tp, "tls"); tls != nil {
			if mode := getString(tls, "mode"); mode != "" {
				return strings.ToUpper(mode)
			}
		}
	}

	return "UNSET"
}

func extractSMCPMTLS(spec map[string]interface{}) string {
	if spec == nil {
		return "UNSET"
	}

	// Check spec.security.dataPlane.mtls (OSSM/Maistra format).
	if security := getMap(spec, "security"); security != nil {
		if dp := getMap(security, "dataPlane"); dp != nil {
			if mtlsVal, ok := dp["mtls"]; ok {
				if b, ok := mtlsVal.(bool); ok {
					if b {
						return "STRICT"
					}
					return "DISABLE"
				}
			}
		}
	}

	return "UNSET"
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
