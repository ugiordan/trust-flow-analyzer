package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestWriteHTMLEmpty(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test-project"}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "<title>Trust Flow Map: test-project</title>") {
		t.Error("missing project title")
	}
	if !strings.Contains(got, "<!DOCTYPE html>") {
		t.Error("missing DOCTYPE")
	}
	if !strings.Contains(got, "</html>") {
		t.Error("missing closing html tag")
	}
}

func TestWriteHTMLAuthFlows(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		AuthFlows: []types.AuthFlow{
			{
				Name: "proxy",
				Entry: types.Location{
					File: "handler.go", Line: 10, Function: "ServeHTTP", Package: "handler",
				},
				Authentication: &types.AuthStep{
					Location: types.Location{
						File: "auth.go", Line: 5, Function: "ValidateToken", Package: "auth",
					},
				},
				Posture: "PERMISSIVE",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()

	checks := []string{
		"Authentication Flows",
		"proxy",
		"handler.go:ServeHTTP (line 10)",
		"auth.go:ValidateToken (line 5)",
		"PERMISSIVE",
		`data-section="auth-flows"`,
	}

	for _, check := range checks {
		if !strings.Contains(got, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestWriteHTMLContradictions(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{
				ID:    "CONTRADICTION-001",
				Title: "test contradiction",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: "a.go", Line: 1, Function: "A"},
						Description: "A assumes B validates",
					},
				},
				Reality:  "Nobody validates",
				Severity: "HIGH",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	checks := []string{
		"Assumption Contradictions",
		"CONTRADICTION-001",
		"test contradiction",
		"severity-high",
		"Nobody validates",
		"A assumes B validates",
	}

	for _, check := range checks {
		if !strings.Contains(got, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestWriteHTMLContradictionsNotCollapsed(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{
				ID:       "C-001",
				Title:    "test",
				Severity: "HIGH",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	// Contradictions section should not have the "collapsed" class
	idx := strings.Index(got, `data-section="contradictions"`)
	if idx == -1 {
		t.Fatal("contradictions section not found")
	}

	// Extract the section div opening tag (look backwards for the <div)
	prefix := got[:idx]
	divIdx := strings.LastIndex(prefix, "<div")
	if divIdx == -1 {
		t.Fatal("could not find section div for contradictions")
	}
	sectionTag := got[divIdx : idx+len(`data-section="contradictions"`)+1]
	if strings.Contains(sectionTag, "collapsed") {
		t.Error("contradictions section should not be collapsed by default")
	}
}

func TestWriteHTMLRouteCoverage(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		RouteCoverage: []types.RouteCoverage{
			{
				Route:     "/api/v1/health",
				RouteKind: "HTTPRoute",
				Backend:   "health-svc",
				Policy:    "health-policy",
				Covered:   true,
				Mechanism: "direct",
			},
			{
				Route:     "/api/v1/admin",
				RouteKind: "HTTPRoute",
				Backend:   "admin-svc",
				Policy:    "NONE",
				Covered:   false,
				Mechanism: "",
			},
			{
				Route:     "/metrics",
				RouteKind: "HTTPRoute",
				Backend:   "metrics-svc",
				Policy:    "skip",
				Covered:   false,
				Mechanism: "INTENTIONAL",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()

	checks := []string{
		"Route Coverage",
		"/api/v1/health",
		"coverage-yes",
		"/api/v1/admin",
		"coverage-no",
		"/metrics",
		"coverage-intentional",
	}

	for _, check := range checks {
		if !strings.Contains(got, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestWriteHTMLDefaults(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		Defaults: []types.DefaultValue{
			{
				Field:           "audiences",
				LibraryDefault:  "nil",
				OperatorDefault: "nil (unchanged)",
				PlatformMeaning: "Accept API server audience",
				Permissiveness:  "PERMISSIVE",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "Configuration Defaults") {
		t.Error("missing defaults section")
	}
	if !strings.Contains(got, "audiences") {
		t.Error("missing audiences field")
	}
}

func TestWriteHTMLSeverityColors(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Kind: "ClusterRole", File: "rbac.yaml", Severity: "HIGH", Rule: "wildcard", Reason: "too broad"},
			{Name: "viewer", Kind: "ClusterRole", File: "rbac.yaml", Severity: "MEDIUM", Rule: "secrets", Reason: "read secrets"},
			{Name: "basic", Kind: "ClusterRole", File: "rbac.yaml", Severity: "LOW", Rule: "pods", Reason: "read pods"},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "severity-high") {
		t.Error("missing severity-high class")
	}
	if !strings.Contains(got, "severity-medium") {
		t.Error("missing severity-medium class")
	}
	if !strings.Contains(got, "severity-low") {
		t.Error("missing severity-low class")
	}
}

func TestWriteHTMLThemeToggle(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test"}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "theme-toggle") {
		t.Error("missing theme toggle button")
	}
	if !strings.Contains(got, "data-theme") {
		t.Error("missing data-theme attribute")
	}
	if !strings.Contains(got, "localStorage") {
		t.Error("missing localStorage for theme persistence")
	}
}

func TestWriteHTMLSearch(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test"}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, `id="search"`) {
		t.Error("missing search input")
	}
	if !strings.Contains(got, "data-searchable") || !strings.Contains(got, "Filter findings") {
		// data-searchable only appears when there are findings, but the search input should always be present
		if !strings.Contains(got, "Filter findings") {
			t.Error("missing search placeholder text")
		}
	}
}

func TestWriteHTMLSummaryDashboard(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		AuthFlows: []types.AuthFlow{
			{Name: "a", Entry: types.Location{File: "a.go", Line: 1}},
			{Name: "b", Entry: types.Location{File: "b.go", Line: 1}},
		},
		Contradictions: []types.Contradiction{
			{ID: "C-1", Severity: "HIGH"},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "summary-grid") {
		t.Error("missing summary grid")
	}
	if !strings.Contains(got, "summary-box") {
		t.Error("missing summary boxes")
	}
}

func TestWriteHTMLInlineCSS(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test"}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "<style>") {
		t.Error("CSS should be inlined in <style> tag")
	}
	if !strings.Contains(got, "<script>") {
		t.Error("JS should be inlined in <script> tag")
	}
	// No external dependencies
	if strings.Contains(got, `<link rel="stylesheet"`) {
		t.Error("should not have external CSS links")
	}
	if strings.Contains(got, `<script src=`) {
		t.Error("should not have external script sources")
	}
}

func TestWriteHTMLErrorPaths(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		ErrorPaths: []types.ErrorPath{
			{
				Origin:   types.Location{File: "handler.go", Line: 42, Function: "Handle"},
				Dropped:  true,
				FailMode: "OPEN",
				Handlers: []types.ErrorHandler{
					{Location: types.Location{File: "log.go", Line: 10, Function: "Log"}, Kind: "LOG"},
				},
			},
			{
				Origin:   types.Location{File: "auth.go", Line: 15, Function: "Check"},
				Dropped:  false,
				FailMode: "CLOSED",
			},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "1 dropped") {
		t.Error("missing dropped count in header")
	}
	if !strings.Contains(got, "DROPPED") {
		t.Error("missing DROPPED status")
	}
	if !strings.Contains(got, "HANDLED") {
		t.Error("missing HANDLED status")
	}
}

func TestWriteHTMLAllSections(t *testing.T) {
	// Verify all 14 section types render without error when populated.
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "full-test",
		AuthFlows: []types.AuthFlow{
			{Name: "flow1", Entry: types.Location{File: "a.go", Line: 1, Function: "F"}, Posture: "RESTRICTIVE"},
		},
		Defaults: []types.DefaultValue{
			{Field: "f1", LibraryDefault: "d1"},
		},
		Contracts: []types.Contract{
			{
				Function:   types.Location{File: "c.go", Line: 1, Function: "C"},
				Violations: []types.ContractViolation{{Caller: types.Location{File: "d.go", Line: 2, Function: "D"}, Kind: "UNCHECKED_ERROR", Description: "err dropped"}},
			},
		},
		ErrorPaths: []types.ErrorPath{
			{Origin: types.Location{File: "e.go", Line: 1, Function: "E"}, FailMode: "CLOSED"},
		},
		Lifecycles: []types.ResourceLifecycle{
			{Resource: "Deployment"},
		},
		SecretExposures: []types.SecretExposure{
			{Location: types.Location{File: "s.go", Line: 1}, Pattern: "ENV_IN_ARGS", Field: "SECRET_KEY", Description: "secret in args"},
		},
		AuthPolicies: []types.AuthPolicyInfo{
			{Name: "pol1", Kind: "AuthPolicy", File: "p.yaml"},
		},
		RouteCoverage: []types.RouteCoverage{
			{Route: "/api", RouteKind: "HTTPRoute", Covered: true, Mechanism: "direct"},
		},
		NetworkPolicies: []types.NetworkPolicyInfo{
			{Name: "np1", File: "np.yaml", PodSelector: "app=test"},
		},
		RBACFindings: []types.RBACFinding{
			{Name: "r1", Kind: "ClusterRole", File: "r.yaml", Severity: "HIGH", Rule: "rule1", Reason: "reason1"},
		},
		MeshPolicies: []types.MeshPolicyInfo{
			{Name: "m1", Kind: "PeerAuthentication", File: "m.yaml", MTLSMode: "STRICT", Scope: "namespace-wide"},
		},
		TemplateRisks: []types.TemplateRisk{
			{File: "t.yaml", Line: 1, Kind: "SECRET_IN_ARGS", Description: "bad", Field: "F", Severity: "HIGH"},
		},
		WebhookDefaults: []types.WebhookDefault{
			{Function: "Default", File: "w.go", Line: 1, FieldsSet: []string{"a"}, FieldsUnset: []string{"b"}},
		},
		Contradictions: []types.Contradiction{
			{ID: "C-1", Title: "t1", Severity: "MEDIUM", Reality: "r1"},
		},
	}

	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}

	got := buf.String()

	sections := []string{
		"auth-flows",
		"defaults",
		"contracts",
		"error-paths",
		"lifecycles",
		"secrets",
		"auth-policies",
		"route-coverage",
		"network-policies",
		"rbac",
		"mesh-policies",
		"template-risks",
		"webhooks",
		"contradictions",
	}

	for _, s := range sections {
		if !strings.Contains(got, `data-section="`+s+`"`) {
			t.Errorf("missing section %q", s)
		}
	}
}
