package synthesis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Synthesize detects contradictions across the analysis results.
// It looks for patterns where components make incompatible assumptions
// about each other (assume-guarantee violations).
// When archCtx is provided, deployment context is used to detect mitigated findings.
func Synthesize(result *types.AnalysisResult, archCtx *passes.ArchContext) {
	var contradictions []types.Contradiction

	contradictions = append(contradictions, detectAuthWithoutAuthz(result)...)
	contradictions = append(contradictions, detectPermissiveDefaults(result)...)
	contradictions = append(contradictions, detectDroppedErrorsOnAuthPath(result)...)
	contradictions = append(contradictions, detectOrphanedResources(result)...)
	contradictions = append(contradictions, detectUncoveredRoutes(result)...)
	contradictions = append(contradictions, detectMissingNetworkPolicies(result)...)
	contradictions = append(contradictions, detectRBACFindings(result)...)
	contradictions = append(contradictions, detectWeakMTLS(result)...)
	contradictions = append(contradictions, detectTemplateRisks(result)...)
	contradictions = append(contradictions, detectInsecureWebhookDefaults(result)...)
	contradictions = append(contradictions, detectOptionalFieldsWithoutValidation(result)...)

	// Apply deployment-context mitigation when arch context is available.
	if archCtx != nil {
		contradictions = detectMitigatedByDeployment(contradictions, archCtx)
	}

	// Sort by severity (HIGH > MEDIUM > LOW) then title for stable ordering,
	// then assign IDs so they are deterministic regardless of detection order.
	sort.Slice(contradictions, func(i, j int) bool {
		si, sj := severityRank(contradictions[i].Severity), severityRank(contradictions[j].Severity)
		if si != sj {
			return si < sj
		}
		return contradictions[i].Title < contradictions[j].Title
	})

	for i := range contradictions {
		contradictions[i].ID = fmt.Sprintf("CONTRADICTION-%03d", i+1)
	}

	result.Contradictions = contradictions
}

func detectAuthWithoutAuthz(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, flow := range result.AuthFlows {
		if flow.Posture != "PERMISSIVE" {
			continue
		}

		if flow.Authentication == nil {
			continue
		}

		// PERMISSIVE posture means authentication exists but authorization does not.
		// No need to check flow.Authorization here since it is always nil for this posture.
		assumptions := []types.Assumption{
			{
				Location:    flow.Authentication.Location,
				Description: flow.Authentication.Location.Function + " authenticates the request",
			},
			{
				Location:    flow.Entry,
				Description: flow.Entry.Function + " has no authorization gate after authentication",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       flow.Name + " path has no effective authorization gate",
			Assumptions: assumptions,
			Reality:     "Authentication success equals authorization. Any valid token grants access.",
			Severity:    "HIGH",
		})
	}

	return contradictions
}

// classifyDefaultDomain returns the security domain for a permissive default field.
// Domains: "auth", "tls", "scope", "proxy", "other".
func classifyDefaultDomain(field string) string {
	lower := strings.ToLower(field)

	// AUTH domain: identity and access control fields.
	authFields := []string{"allowedgroups", "audiences", "email-domain", "emaildomain",
		"allowedorganizations", "allowedemails"}
	for _, af := range authFields {
		if strings.Contains(lower, af) {
			return "auth"
		}
	}

	// TLS domain: transport security fields.
	tlsFields := []string{"insecureskipverify", "sslmode", "insecureskipnonce", "tlsskipverify"}
	for _, tf := range tlsFields {
		if strings.Contains(lower, tf) {
			return "tls"
		}
	}

	// SCOPE domain: namespace/cluster-wide access fields.
	if lower == "namespace" || strings.Contains(lower, "watchnamespace") {
		return "scope"
	}

	// PROXY domain: optional auth sidecar components.
	proxyFields := []string{"kuberbacproxy", "oauthproxy", "authorino"}
	for _, pf := range proxyFields {
		if strings.Contains(lower, pf) {
			return "proxy"
		}
	}

	return "other"
}

func detectPermissiveDefaults(result *types.AnalysisResult) []types.Contradiction {
	var permissive []types.DefaultValue
	for _, d := range result.Defaults {
		if d.Permissiveness == "PERMISSIVE" {
			permissive = append(permissive, d)
		}
	}

	if len(permissive) == 0 {
		return nil
	}

	// Group permissive defaults by security domain.
	domainDefaults := make(map[string][]types.DefaultValue)
	for _, d := range permissive {
		domain := classifyDefaultDomain(d.Field)
		domainDefaults[domain] = append(domainDefaults[domain], d)
	}

	var contradictions []types.Contradiction

	// Generate domain-specific contradictions.
	for domain, defaults := range domainDefaults {
		if domain == "other" {
			continue
		}

		var assumptions []types.Assumption
		for _, d := range defaults {
			assumptions = append(assumptions, types.Assumption{
				Location:    d.Location,
				Description: d.Field + " defaults to " + d.LibraryDefault + " (" + d.PlatformMeaning + ")",
			})
		}

		var severity, title, reality string
		switch domain {
		case "auth":
			if len(defaults) >= 2 {
				severity = "HIGH"
				title = "Multiple authentication fields default to permissive values"
				reality = fmt.Sprintf("%d authentication fields default to permissive values. Combined effect: any authenticated user from any domain/organization is authorized.", len(defaults))
			} else {
				severity = "MEDIUM"
				title = defaults[0].Field + " defaults to permissive value"
				reality = defaults[0].Field + " defaults to " + defaults[0].LibraryDefault + ". " + defaults[0].PlatformMeaning + "."
			}
		case "tls":
			severity = "MEDIUM"
			title = "Transport security fields default to permissive values"
			reality = fmt.Sprintf("%d TLS/SSL fields default to insecure values. Transport layer security is weakened.", len(defaults))
		case "proxy":
			if len(defaults) >= 2 {
				severity = "HIGH"
				title = "Multiple auth proxy components are optional by default"
				reality = fmt.Sprintf("%d auth proxy/sidecar components are absent by default. No authentication sidecar fallback exists.", len(defaults))
			} else {
				severity = "MEDIUM"
				title = defaults[0].Field + " auth proxy is optional by default"
				reality = defaults[0].Field + " is absent by default. " + defaults[0].PlatformMeaning + "."
			}
		case "scope":
			severity = "MEDIUM"
			title = "Namespace scope defaults to cluster-wide access"
			reality = "Namespace field defaults to empty, granting cluster-wide access instead of namespace-scoped."
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       title,
			Assumptions: assumptions,
			Reality:     reality,
			Severity:    severity,
		})
	}

	// Cross-domain interaction: AUTH + SCOPE = cluster-wide open access.
	if len(domainDefaults["auth"]) > 0 && len(domainDefaults["scope"]) > 0 {
		var assumptions []types.Assumption
		for _, d := range domainDefaults["auth"] {
			assumptions = append(assumptions, types.Assumption{
				Location:    d.Location,
				Description: d.Field + " defaults to " + d.LibraryDefault + " (" + d.PlatformMeaning + ")",
			})
		}
		for _, d := range domainDefaults["scope"] {
			assumptions = append(assumptions, types.Assumption{
				Location:    d.Location,
				Description: d.Field + " defaults to " + d.LibraryDefault + " (" + d.PlatformMeaning + ")",
			})
		}
		contradictions = append(contradictions, types.Contradiction{
			Title:       "Cluster-wide open access: permissive auth combined with cluster scope",
			Assumptions: assumptions,
			Reality:     "Authentication fields accept any user/domain AND namespace scope defaults to cluster-wide. Combined effect: any authenticated user has cluster-wide access.",
			Severity:    "HIGH",
		})
	}

	return contradictions
}

// functionKey produces a key identifying a function by package, name, and file
// (without line number). This is used for cross-referencing between analysis
// passes where the same function appears with different line numbers: auth flow
// locations use the function definition line, while error path origins use the
// error creation call-site line.
func functionKey(loc types.Location) string {
	return fmt.Sprintf("%s.%s@%s", loc.Package, loc.Function, loc.File)
}

func detectDroppedErrorsOnAuthPath(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	// Build a set of auth-related functions keyed by package.function@file.
	// Line numbers are excluded because auth locations use fn.Pos() (definition line)
	// while error origins use call.Pos() (call-site line within the function).
	authFunctions := make(map[string]bool)
	for _, flow := range result.AuthFlows {
		authFunctions[functionKey(flow.Entry)] = true
		if flow.Authentication != nil {
			authFunctions[functionKey(flow.Authentication.Location)] = true
		}
		if flow.Authorization != nil {
			authFunctions[functionKey(flow.Authorization.Location)] = true
		}
		for _, v := range flow.Validators {
			authFunctions[functionKey(v.Location)] = true
		}
	}

	for _, ep := range result.ErrorPaths {
		if !ep.Dropped {
			continue
		}
		funcKey := functionKey(ep.Origin)
		if !authFunctions[funcKey] {
			continue
		}

		contradictions = append(contradictions, types.Contradiction{
			Title: "Error in " + ep.Origin.Function + " silently dropped on auth path",
			Assumptions: []types.Assumption{
				{
					Location:    ep.Origin,
					Description: ep.Origin.Function + " creates an error that is never handled",
				},
			},
			Reality:  "Error on authentication/authorization path is dropped. Failure may silently allow access (fail-open: " + ep.FailMode + ").",
			Severity: "HIGH",
		})
	}

	return contradictions
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

func detectUncoveredRoutes(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, cov := range result.RouteCoverage {
		if cov.Covered || cov.Mechanism == "INTENTIONAL" {
			continue
		}

		assumptions := []types.Assumption{
			{
				Location: types.Location{
					File: cov.RouteFile,
				},
				Description: cov.RouteKind + " " + cov.Route + " exposes backend " + cov.Backend + " without auth policy",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       cov.Route + " route has no auth policy coverage",
			Assumptions: assumptions,
			Reality:     "Route " + cov.Route + " in " + cov.RouteFile + " has no matching AuthPolicy, AuthConfig, or gateway-level default. Traffic to this route is unauthenticated.",
			Severity:    "MEDIUM",
			Mitigation:  "Add an AuthPolicy targeting the route or its parent gateway.",
		})
	}

	return contradictions
}

func detectOrphanedResources(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, lc := range result.Lifecycles {
		if !lc.Orphanable || lc.Create == nil {
			continue
		}

		assumptions := []types.Assumption{
			{
				Location:    *lc.Create,
				Description: lc.Create.Function + " creates " + lc.Resource + " without owner reference or finalizer",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       lc.Resource + " created without ownership or cleanup mechanism",
			Assumptions: assumptions,
			Reality:     "Resource " + lc.Resource + " has no owner reference or finalizer. If the parent is deleted, this resource will be orphaned.",
			Severity:    "LOW",
		})
	}

	return contradictions
}

// detectMissingNetworkPolicies flags services referenced by HTTPRoutes/backendRefs
// that have no matching NetworkPolicy podSelector. Only fires if the project has
// at least one NetworkPolicy (projects without any are not flagged).
func detectMissingNetworkPolicies(result *types.AnalysisResult) []types.Contradiction {
	if len(result.NetworkPolicies) == 0 {
		return nil
	}

	// Build a set of pod selector labels from all NetworkPolicies.
	coveredSelectors := make(map[string]bool)
	for _, np := range result.NetworkPolicies {
		if np.PodSelector != "" && np.PodSelector != "(all pods)" {
			coveredSelectors[np.PodSelector] = true
		}
	}

	// Collect backend service names from route coverage.
	type backendRef struct {
		name string
		file string
	}
	seen := make(map[string]bool)
	var backends []backendRef
	for _, cov := range result.RouteCoverage {
		if cov.Backend != "" && !seen[cov.Backend] {
			seen[cov.Backend] = true
			backends = append(backends, backendRef{name: cov.Backend, file: cov.RouteFile})
		}
	}

	var contradictions []types.Contradiction
	for _, backend := range backends {
		// Check if any NetworkPolicy podSelector mentions this backend name.
		covered := false
		for selector := range coveredSelectors {
			// Simple heuristic: check if the backend name appears in a selector value.
			if containsServiceName(selector, backend.name) {
				covered = true
				break
			}
		}

		if !covered {
			contradictions = append(contradictions, types.Contradiction{
				Title: backend.name + " has no NetworkPolicy coverage",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: backend.file},
						Description: "HTTPRoute routes traffic to backend " + backend.name + " but no NetworkPolicy selects it",
					},
				},
				Reality:    "Service " + backend.name + " is exposed via HTTPRoute but has no NetworkPolicy restricting ingress/egress. Any pod in the namespace can reach it.",
				Severity:   "MEDIUM",
				Mitigation: "Add a NetworkPolicy with a podSelector matching the " + backend.name + " pods.",
			})
		}
	}

	return contradictions
}

// containsServiceName checks if a label selector references a service name.
// Matches patterns like "app=my-service" or "component=my-service".
func containsServiceName(selector, serviceName string) bool {
	// Split selector into individual label pairs and check values.
	pairs := splitLabels(selector)
	for _, pair := range pairs {
		parts := splitOnce(pair, "=")
		if len(parts) == 2 && parts[1] == serviceName {
			return true
		}
	}
	return false
}

func splitLabels(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		trimmed := trimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	// If no comma found, return the original as a single-element slice.
	if len(result) == 0 && s != "" {
		return []string{trimSpace(s)}
	}
	return result
}

func splitOnce(s, sep string) []string {
	idx := indexOf(s, sep)
	if idx < 0 {
		return []string{s}
	}
	return []string{s[:idx], s[idx+len(sep):]}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// detectRBACFindings converts each RBAC finding into a contradiction.
func detectRBACFindings(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, f := range result.RBACFindings {
		contradictions = append(contradictions, types.Contradiction{
			Title: f.Name + " " + f.Kind + " is overprivileged",
			Assumptions: []types.Assumption{
				{
					Location:    types.Location{File: f.File},
					Description: f.Kind + " " + f.Name + " grants " + f.Rule,
				},
			},
			Reality:    f.Reason,
			Severity:   f.Severity,
			Mitigation: "Reduce scope to namespace-scoped Role or restrict resource/verb combinations.",
		})
	}

	return contradictions
}

// detectTemplateRisks converts SECRET_IN_ARGS and CONDITIONAL_SECURITY template
// risks into contradictions. CONDITIONAL_SECURITY findings are cross-referenced
// with the defaults pass to strengthen the signal when the controlling field is
// known to be optional.
func detectTemplateRisks(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, risk := range result.TemplateRisks {
		switch risk.Kind {
		case "SECRET_IN_ARGS":
			contradictions = append(contradictions, types.Contradiction{
				Title: "Secret exposed in container args via " + risk.Field,
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: risk.File, Line: risk.Line},
						Description: "Template expands " + risk.Field + " in container args/command",
					},
				},
				Reality:    "Kubelet expands env vars in container args into /proc/1/cmdline. The secret value is visible to any process that can read /proc on the node.",
				Severity:   "HIGH",
				Mitigation: "Mount secrets as files or use environment variables directly (without expanding in args). Avoid $(SECRET) in container args.",
			})
		case "CONDITIONAL_SECURITY":
			contradictions = append(contradictions, types.Contradiction{
				Title: "Security component conditional on " + risk.Field,
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: risk.File, Line: risk.Line},
						Description: "Template only deploys security component when " + risk.Field + " is set",
					},
				},
				Reality:    "If the CRD field " + risk.Field + " is optional (pointer type with +optional), the security component is absent by default. Users must explicitly opt in.",
				Severity:   "MEDIUM",
				Mitigation: "Consider making the security component deploy by default, or ensure the CRD field has a secure default value.",
			})
		}
	}

	return contradictions
}

// detectInsecureWebhookDefaults generates contradictions when a webhook Default()
// method sets a security-relevant field to an insecure value, or when it leaves
// security fields unset.
func detectInsecureWebhookDefaults(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	// Cross-reference webhook defaults with the defaults pass to find insecure
	// values being set by the defaulter.
	insecureValues := map[string]bool{
		"disable":  true,
		"disabled": true,
		"false":    true,
		"none":     true,
		"off":      true,
	}

	for _, wd := range result.WebhookDefaults {
		// Check if any of the set fields have insecure default values from the
		// defaults pass.
		for _, field := range wd.FieldsSet {
			for _, d := range result.Defaults {
				if !strings.HasSuffix(d.Field, field) {
					continue
				}
				lowerVal := strings.ToLower(d.LibraryDefault)
				if insecureValues[lowerVal] {
					contradictions = append(contradictions, types.Contradiction{
						Title: wd.Function + " sets " + field + " to insecure default",
						Assumptions: []types.Assumption{
							{
								Location:    types.Location{File: wd.File, Line: wd.Line},
								Description: wd.Function + " sets " + field + " to " + d.LibraryDefault,
							},
						},
						Reality:    "Webhook defaulter sets " + field + " to an insecure value (" + d.LibraryDefault + "). New CRD instances will have this security feature disabled unless the user explicitly overrides it.",
						Severity:   "MEDIUM",
						Mitigation: "Change the webhook default to a secure value, or require the user to explicitly set this field.",
					})
				}
			}
		}
	}

	return contradictions
}

// detectOptionalFieldsWithoutValidation cross-references WebhookDefaults with
// WebhookValidations. For each field that Default() does not set (FieldsUnset),
// check if any ValidateCreate/ValidateUpdate/ValidateDelete covers that field.
// If the field is neither defaulted nor validated, it is truly optional with no
// safety net, which is a MEDIUM contradiction.
func detectOptionalFieldsWithoutValidation(result *types.AnalysisResult) []types.Contradiction {
	// Build a set of fields checked by any validation webhook.
	validatedFields := make(map[string]bool)
	for _, wv := range result.WebhookValidations {
		for _, f := range wv.FieldsChecked {
			validatedFields[f] = true
		}
	}

	var contradictions []types.Contradiction

	for _, wd := range result.WebhookDefaults {
		for _, field := range wd.FieldsUnset {
			if validatedFields[field] {
				// Default() doesn't set it, but Validate() checks it.
				// This is enforced by webhook validation, skip the contradiction.
				continue
			}

			// Neither defaulted nor validated. Truly optional with no safety net.
			contradictions = append(contradictions, types.Contradiction{
				Title: field + " is optional with no defaulting or validation",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: wd.File, Line: wd.Line},
						Description: wd.Function + " does not default " + field + " and no validator checks it",
					},
				},
				Reality:    "Security field " + field + " is neither set by the webhook defaulter nor checked by any validation webhook. Users can deploy without this security component and no webhook will warn them.",
				Severity:   "MEDIUM",
				Mitigation: "Add a validation check for " + field + " in ValidateCreate/ValidateUpdate, or set a secure default in the Default() webhook.",
			})
		}
	}

	return contradictions
}

// authSidecarPatterns are container/sidecar name substrings that indicate
// an authentication proxy is deployed alongside the application.
var authSidecarPatterns = []string{
	"rbac-proxy",
	"oauth-proxy",
	"authorino",
	"envoy",
}

// detectMitigatedByDeployment checks if "no auth in code" findings are mitigated
// by deployment context. When an ArchContext shows a sidecar with a known auth proxy
// pattern, the corresponding contradiction is downgraded from HIGH to LOW and a
// Mitigation note is added.
func detectMitigatedByDeployment(contradictions []types.Contradiction, archCtx *passes.ArchContext) []types.Contradiction {
	if archCtx == nil || len(archCtx.Deployments) == 0 {
		return contradictions
	}

	// Build a map of deployment names to their auth sidecar names.
	type sidecarInfo struct {
		deploymentName string
		sidecarName    string
	}
	var authSidecars []sidecarInfo

	for _, dep := range archCtx.Deployments {
		// Check both containers and sidecars for auth proxy patterns.
		allContainers := append(dep.Containers, dep.Sidecars...)
		for _, container := range allContainers {
			lower := strings.ToLower(container)
			for _, pattern := range authSidecarPatterns {
				if strings.Contains(lower, pattern) {
					authSidecars = append(authSidecars, sidecarInfo{
						deploymentName: dep.Name,
						sidecarName:    container,
					})
					break
				}
			}
		}
	}

	if len(authSidecars) == 0 {
		return contradictions
	}

	// Apply mitigation to auth-related contradictions.
	for i := range contradictions {
		c := &contradictions[i]

		// Only mitigate PERMISSIVE auth / "no auth" / "no authorization" contradictions.
		isAuthContradiction := false
		lower := strings.ToLower(c.Title)
		if strings.Contains(lower, "no effective authorization") ||
			strings.Contains(lower, "no auth") ||
			strings.Contains(lower, "permissive") {
			isAuthContradiction = true
		}
		if strings.Contains(lower, "auth proxy") && strings.Contains(lower, "optional") {
			isAuthContradiction = true
		}

		if !isAuthContradiction {
			continue
		}

		// Use the first matching auth sidecar for the mitigation message.
		sc := authSidecars[0]
		c.Mitigation = fmt.Sprintf("Mitigated by %s sidecar in deployment %s", sc.sidecarName, sc.deploymentName)

		if c.Severity == "HIGH" {
			c.Severity = "LOW"
		}
	}

	return contradictions
}

// detectWeakMTLS flags PERMISSIVE or DISABLE mTLS modes as contradictions.
func detectWeakMTLS(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, mp := range result.MeshPolicies {
		switch mp.MTLSMode {
		case "PERMISSIVE":
			contradictions = append(contradictions, types.Contradiction{
				Title: mp.Name + " uses PERMISSIVE mTLS",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: mp.File},
						Description: mp.Kind + " " + mp.Name + " sets mTLS to PERMISSIVE (" + mp.Scope + ")",
					},
				},
				Reality:    "PERMISSIVE mTLS allows both plaintext and encrypted traffic. Attackers can downgrade connections to plaintext.",
				Severity:   "LOW",
				Mitigation: "Set mTLS mode to STRICT to enforce encrypted service-to-service communication.",
			})
		case "DISABLE":
			contradictions = append(contradictions, types.Contradiction{
				Title: mp.Name + " disables mTLS",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: mp.File},
						Description: mp.Kind + " " + mp.Name + " sets mTLS to DISABLE (" + mp.Scope + ")",
					},
				},
				Reality:    "mTLS is disabled. All service-to-service traffic is plaintext and vulnerable to eavesdropping and tampering.",
				Severity:   "MEDIUM",
				Mitigation: "Enable mTLS (STRICT mode) to encrypt service-to-service communication.",
			})
		}
	}

	return contradictions
}
