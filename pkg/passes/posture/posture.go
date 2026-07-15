package posture

import (
	"fmt"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass evaluates the project against expected security controls and produces
// a pass/fail checklist. It runs AFTER all other passes and synthesis, reading
// the fully populated AnalysisResult to derive posture checks.
type Pass struct{}

func (p *Pass) Name() string { return "posture" }

func (p *Pass) Run(ctx *passes.Context) error {
	result := ctx.Result

	var checks []types.PostureCheck

	checks = append(checks, checkNetworkPolicyCoverage(result))
	checks = append(checks, checkRBACScope(result))
	checks = append(checks, checkMTLSMode(result))
	checks = append(checks, checkAuthPolicyCoverage(result))
	checks = append(checks, checkErrorHandlingOnAuthPaths(result))
	checks = append(checks, checkSecretManagement(result))
	checks = append(checks, checkOptionalSecurityComponents(result))
	checks = append(checks, checkConfigDefaultsPosture(result))
	checks = append(checks, checkResourceLifecycle(result))

	result.PostureChecks = checks
	return nil
}

// Score computes a posture score from the checklist. PASS=1, PARTIAL=0.5,
// FAIL=0, N/A=excluded. Returns a percentage.
func Score(checks []types.PostureCheck) float64 {
	var total, score float64
	for _, c := range checks {
		switch c.Status {
		case "N/A":
			continue
		case "PASS":
			total++
			score++
		case "PARTIAL":
			total++
			score += 0.5
		case "FAIL":
			total++
		}
	}
	if total == 0 {
		return 100.0
	}
	return (score / total) * 100.0
}

// checkNetworkPolicyCoverage: PASS if all services have NetworkPolicies,
// FAIL if any don't, N/A if no NetworkPolicies exist at all.
func checkNetworkPolicyCoverage(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "NetworkPolicy coverage",
		Category: "network",
	}

	if len(result.NetworkPolicies) == 0 {
		check.Status = "N/A"
		check.Details = "No NetworkPolicies found in project"
		return check
	}

	// Count services without NetworkPolicy coverage from contradictions.
	uncoveredCount := 0
	for _, c := range result.Contradictions {
		if strings.Contains(c.Title, "has no NetworkPolicy coverage") {
			uncoveredCount++
		}
	}

	if uncoveredCount == 0 {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("All services covered (%d policies)", len(result.NetworkPolicies))
	} else {
		check.Status = "FAIL"
		check.Severity = "MEDIUM"
		check.Details = fmt.Sprintf("%d service(s) without NetworkPolicy coverage", uncoveredCount)
	}
	return check
}

// checkRBACScope: PASS if no HIGH RBAC findings, FAIL if any cluster-scope
// secrets CRUD exists.
func checkRBACScope(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "RBAC scope",
		Category: "rbac",
	}

	if len(result.RBACFindings) == 0 {
		check.Status = "N/A"
		check.Details = "No RBAC findings"
		return check
	}

	highCount := 0
	for _, f := range result.RBACFindings {
		if strings.ToUpper(f.Severity) == "HIGH" {
			highCount++
		}
	}

	if highCount == 0 {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("No HIGH RBAC findings (%d total findings)", len(result.RBACFindings))
	} else {
		check.Status = "FAIL"
		check.Severity = "HIGH"
		check.Details = fmt.Sprintf("%d HIGH RBAC finding(s) detected (e.g. cluster-wide secrets CRUD)", highCount)
	}
	return check
}

// checkMTLSMode: PASS if all policies are STRICT, FAIL if any PERMISSIVE/DISABLE,
// N/A if no mesh policies exist.
func checkMTLSMode(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "mTLS mode",
		Category: "tls",
	}

	if len(result.MeshPolicies) == 0 {
		check.Status = "N/A"
		check.Details = "No service mesh policies found"
		return check
	}

	weakCount := 0
	for _, mp := range result.MeshPolicies {
		mode := strings.ToUpper(mp.MTLSMode)
		if mode == "PERMISSIVE" || mode == "DISABLE" {
			weakCount++
		}
	}

	if weakCount == 0 {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("All %d mesh policies use STRICT mTLS", len(result.MeshPolicies))
	} else {
		check.Status = "FAIL"
		check.Severity = "MEDIUM"
		check.Details = fmt.Sprintf("%d/%d mesh policies use PERMISSIVE or DISABLE mTLS", weakCount, len(result.MeshPolicies))
	}
	return check
}

// checkAuthPolicyCoverage: PASS if all routes covered, FAIL if uncovered routes
// exist, N/A if no routes.
func checkAuthPolicyCoverage(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Auth policy coverage",
		Category: "auth",
	}

	if len(result.RouteCoverage) == 0 {
		check.Status = "N/A"
		check.Details = "No routes found"
		return check
	}

	covered := 0
	total := 0
	for _, rc := range result.RouteCoverage {
		total++
		if rc.Covered || strings.EqualFold(rc.Mechanism, "INTENTIONAL") {
			covered++
		}
	}

	if covered == total {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("All %d routes covered by auth policies", total)
	} else if covered > 0 {
		check.Status = "PARTIAL"
		check.Details = fmt.Sprintf("%d/%d routes covered by auth policies", covered, total)
	} else {
		check.Status = "FAIL"
		check.Severity = "HIGH"
		check.Details = fmt.Sprintf("0/%d routes covered by auth policies", total)
	}
	return check
}

// checkErrorHandlingOnAuthPaths: PASS if no dropped errors on auth paths,
// FAIL if any exist.
func checkErrorHandlingOnAuthPaths(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Error handling on auth paths",
		Category: "auth",
	}

	droppedOnAuth := 0
	for _, c := range result.Contradictions {
		if strings.Contains(c.Title, "silently dropped on auth path") {
			droppedOnAuth++
		}
	}

	if droppedOnAuth == 0 {
		check.Status = "PASS"
		check.Details = "No dropped errors on authentication/authorization paths"
	} else {
		check.Status = "FAIL"
		check.Severity = "HIGH"
		check.Details = fmt.Sprintf("%d error(s) dropped on auth paths (potential fail-open)", droppedOnAuth)
	}
	return check
}

// checkSecretManagement: PASS if no SECRET_IN_ARGS template risks,
// FAIL if any exist.
func checkSecretManagement(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Secret management",
		Category: "auth",
	}

	secretInArgs := 0
	for _, tr := range result.TemplateRisks {
		if tr.Kind == "SECRET_IN_ARGS" {
			secretInArgs++
		}
	}

	if secretInArgs == 0 {
		check.Status = "PASS"
		check.Details = "No secrets exposed in container args"
	} else {
		check.Status = "FAIL"
		check.Severity = "HIGH"
		check.Details = fmt.Sprintf("%d secret(s) exposed in container args via template expansion", secretInArgs)
	}
	return check
}

// checkOptionalSecurityComponents: PASS if webhook validates auth proxy
// fields, FAIL if truly optional (no default, no validation).
func checkOptionalSecurityComponents(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Optional security components",
		Category: "lifecycle",
	}

	// Count contradictions about optional fields without validation.
	unprotected := 0
	for _, c := range result.Contradictions {
		if strings.Contains(c.Title, "optional with no defaulting or validation") {
			unprotected++
		}
	}

	if len(result.WebhookDefaults) == 0 && len(result.WebhookValidations) == 0 {
		check.Status = "N/A"
		check.Details = "No webhook defaulters or validators found"
		return check
	}

	if unprotected == 0 {
		check.Status = "PASS"
		check.Details = "All optional security fields are either defaulted or validated"
	} else {
		check.Status = "FAIL"
		check.Severity = "MEDIUM"
		check.Details = fmt.Sprintf("%d security field(s) are optional with no defaulting or validation", unprotected)
	}
	return check
}

// checkConfigDefaultsPosture: PASS if no permissive defaults, PARTIAL if
// some exist with mitigations.
func checkConfigDefaultsPosture(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Config defaults posture",
		Category: "auth",
	}

	permissiveCount := 0
	for _, d := range result.Defaults {
		if d.Permissiveness == "PERMISSIVE" {
			permissiveCount++
		}
	}

	if permissiveCount == 0 {
		check.Status = "PASS"
		check.Details = "No permissive defaults detected"
		return check
	}

	// Check if there are mitigations (webhook defaults setting these fields,
	// or validation webhooks checking them).
	mitigatedCount := 0

	// Build a set of fields covered by webhook defaulters.
	defaultedFields := make(map[string]bool)
	for _, wd := range result.WebhookDefaults {
		for _, f := range wd.FieldsSet {
			defaultedFields[strings.ToLower(f)] = true
		}
	}
	validatedFields := make(map[string]bool)
	for _, wv := range result.WebhookValidations {
		for _, f := range wv.FieldsChecked {
			validatedFields[strings.ToLower(f)] = true
		}
	}

	for _, d := range result.Defaults {
		if d.Permissiveness != "PERMISSIVE" {
			continue
		}
		fieldLower := strings.ToLower(d.Field)
		// Check if the last component of the field name is covered.
		parts := strings.Split(fieldLower, ".")
		lastPart := parts[len(parts)-1]
		if defaultedFields[lastPart] || validatedFields[lastPart] {
			mitigatedCount++
		}
	}

	if mitigatedCount >= permissiveCount {
		check.Status = "PASS"
		check.Details = fmt.Sprintf("%d permissive defaults, all mitigated by webhooks", permissiveCount)
	} else if mitigatedCount > 0 {
		check.Status = "PARTIAL"
		check.Details = fmt.Sprintf("%d permissive defaults (%d mitigated by webhooks)", permissiveCount, mitigatedCount)
	} else {
		check.Status = "FAIL"
		check.Severity = "MEDIUM"
		check.Details = fmt.Sprintf("%d permissive defaults with no webhook mitigation", permissiveCount)
	}
	return check
}

// checkResourceLifecycle: PASS if no orphanable resources, FAIL if any exist.
func checkResourceLifecycle(result *types.AnalysisResult) types.PostureCheck {
	check := types.PostureCheck{
		Name:     "Resource lifecycle",
		Category: "lifecycle",
	}

	if len(result.Lifecycles) == 0 {
		check.Status = "N/A"
		check.Details = "No resource lifecycles tracked"
		return check
	}

	orphanable := 0
	for _, lc := range result.Lifecycles {
		if lc.Orphanable {
			orphanable++
		}
	}

	if orphanable == 0 {
		check.Status = "PASS"
		check.Details = "All resources have owner references or finalizers"
	} else {
		check.Status = "FAIL"
		check.Severity = "LOW"
		check.Details = fmt.Sprintf("%d resource(s) can be orphaned (no owner reference or finalizer)", orphanable)
	}
	return check
}
