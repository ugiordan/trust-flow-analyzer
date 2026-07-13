package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "empty-project"}

	if err := WriteSARIF(&buf, result, "1.0.0"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	if len(log.Runs[0].Results) != 0 {
		t.Errorf("results = %d, want 0", len(log.Runs[0].Results))
	}
	if len(log.Runs[0].Tool.Driver.Rules) != 0 {
		t.Errorf("rules = %d, want 0", len(log.Runs[0].Tool.Driver.Rules))
	}
	if log.Runs[0].Tool.Driver.Version != "1.0.0" {
		t.Errorf("tool version = %q, want 1.0.0", log.Runs[0].Tool.Driver.Version)
	}
}

func TestSARIFContradictions(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{
				ID:    "C-001",
				Title: "mTLS assumption mismatch",
				Assumptions: []types.Assumption{
					{
						Location:    types.Location{File: "server.go", Line: 42, Function: "Init"},
						Description: "assumes mTLS is enforced",
					},
				},
				Reality:  "mTLS is permissive",
				Severity: "HIGH",
			},
			{
				ID:       "C-002",
				Title:    "minor config gap",
				Severity: "LOW",
			},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	results := log.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2", len(results))
	}

	// First contradiction: HIGH -> error level
	r0 := results[0]
	if r0.RuleID != "TFA-CONTRADICTION-HIGH" {
		t.Errorf("ruleId = %q, want TFA-CONTRADICTION-HIGH", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("level = %q, want error", r0.Level)
	}
	if !strings.Contains(r0.Message.Text, "C-001") {
		t.Errorf("message missing contradiction ID, got %q", r0.Message.Text)
	}
	if !strings.Contains(r0.Message.Text, "mTLS assumption mismatch") {
		t.Errorf("message missing title, got %q", r0.Message.Text)
	}
	if len(r0.Locations) != 1 {
		t.Fatalf("locations = %d, want 1", len(r0.Locations))
	}
	if r0.Locations[0].PhysicalLocation.ArtifactLocation.URI != "server.go" {
		t.Errorf("location URI = %q, want server.go", r0.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if r0.Locations[0].PhysicalLocation.Region == nil || r0.Locations[0].PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("location line = %v, want 42", r0.Locations[0].PhysicalLocation.Region)
	}
	if r0.Properties["trust-flow-analyzer/pass"] != "Contradiction" {
		t.Errorf("pass property = %q, want Contradiction", r0.Properties["trust-flow-analyzer/pass"])
	}

	// Second contradiction: LOW -> note level
	r1 := results[1]
	if r1.RuleID != "TFA-CONTRADICTION-LOW" {
		t.Errorf("ruleId = %q, want TFA-CONTRADICTION-LOW", r1.RuleID)
	}
	if r1.Level != "note" {
		t.Errorf("level = %q, want note", r1.Level)
	}

	// Check rules are collected
	rules := log.Runs[0].Tool.Driver.Rules
	if len(rules) != 2 {
		t.Fatalf("rules = %d, want 2", len(rules))
	}
	ruleIDs := make(map[string]bool)
	for _, rule := range rules {
		ruleIDs[rule.ID] = true
	}
	if !ruleIDs["TFA-CONTRADICTION-HIGH"] {
		t.Error("missing rule TFA-CONTRADICTION-HIGH")
	}
	if !ruleIDs["TFA-CONTRADICTION-LOW"] {
		t.Error("missing rule TFA-CONTRADICTION-LOW")
	}
}

func TestSARIFAuthFlows(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		AuthFlows: []types.AuthFlow{
			{
				Name:    "proxy",
				Entry:   types.Location{File: "handler.go", Line: 10, Function: "ServeHTTP"},
				Posture: "PERMISSIVE",
			},
			{
				Name:    "internal",
				Entry:   types.Location{File: "internal.go", Line: 5, Function: "Handle"},
				Posture: "RESTRICTIVE",
			},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	results := log.Runs[0].Results
	// Only PERMISSIVE flows produce results
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1 (only PERMISSIVE)", len(results))
	}

	r := results[0]
	if r.RuleID != "TFA-AUTH-PERMISSIVE" {
		t.Errorf("ruleId = %q, want TFA-AUTH-PERMISSIVE", r.RuleID)
	}
	if r.Level != "warning" {
		t.Errorf("level = %q, want warning", r.Level)
	}
	if !strings.Contains(r.Message.Text, "proxy") {
		t.Errorf("message should mention flow name, got %q", r.Message.Text)
	}
	if r.Properties["trust-flow-analyzer/pass"] != "AuthFlow" {
		t.Errorf("pass property = %q, want AuthFlow", r.Properties["trust-flow-analyzer/pass"])
	}
	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "handler.go" {
		t.Errorf("location should point to handler.go")
	}
}

func TestSARIFRBACFindings(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Kind: "ClusterRole", File: "rbac.yaml", Severity: "HIGH", Rule: "wildcard", Reason: "wildcard verbs"},
			{Name: "viewer", Kind: "ClusterRole", File: "rbac.yaml", Severity: "MEDIUM", Rule: "secrets", Reason: "read secrets"},
			{Name: "basic", Kind: "ClusterRole", File: "rbac.yaml", Severity: "LOW", Rule: "pods", Reason: "read pods"},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	results := log.Runs[0].Results
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3", len(results))
	}

	expected := []struct {
		ruleID string
		level  string
	}{
		{"TFA-RBAC-HIGH", "error"},
		{"TFA-RBAC-MEDIUM", "warning"},
		{"TFA-RBAC-LOW", "note"},
	}

	for i, exp := range expected {
		if results[i].RuleID != exp.ruleID {
			t.Errorf("results[%d].ruleId = %q, want %q", i, results[i].RuleID, exp.ruleID)
		}
		if results[i].Level != exp.level {
			t.Errorf("results[%d].level = %q, want %q", i, results[i].Level, exp.level)
		}
		if results[i].Properties["trust-flow-analyzer/pass"] != "RBAC" {
			t.Errorf("results[%d] pass = %q, want RBAC", i, results[i].Properties["trust-flow-analyzer/pass"])
		}
	}
}

func TestSARIFSchema(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test"}

	if err := WriteSARIF(&buf, result, "1.2.3"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	got := buf.String()

	if !strings.Contains(got, `"version": "2.1.0"`) {
		t.Error("missing SARIF version 2.1.0")
	}
	if !strings.Contains(got, `"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"`) {
		t.Error("missing SARIF schema URL")
	}
	if !strings.Contains(got, `"name": "trust-flow-analyzer"`) {
		t.Error("missing tool name")
	}
	if !strings.Contains(got, `"informationUri": "https://github.com/ugiordan/trust-flow-analyzer"`) {
		t.Error("missing tool informationUri")
	}
	if !strings.Contains(got, `"version": "1.2.3"`) {
		t.Error("missing tool version")
	}
}

func TestSARIFAllFindingTypes(t *testing.T) {
	// Verify all 11 finding types produce SARIF results.
	var buf bytes.Buffer
	createLoc := types.Location{File: "create.go", Line: 5, Function: "Create"}
	result := &types.AnalysisResult{
		Project: "full-test",
		Contradictions: []types.Contradiction{
			{ID: "C-1", Title: "t", Severity: "HIGH", Assumptions: []types.Assumption{{Location: types.Location{File: "a.go", Line: 1}}}},
		},
		AuthFlows: []types.AuthFlow{
			{Name: "f1", Entry: types.Location{File: "h.go", Line: 1}, Posture: "PERMISSIVE"},
		},
		Contracts: []types.Contract{
			{Function: types.Location{File: "c.go", Line: 1}, Violations: []types.ContractViolation{{Caller: types.Location{File: "d.go", Line: 2}, Kind: "UNCHECKED_ERROR", Description: "err dropped"}}},
		},
		ErrorPaths: []types.ErrorPath{
			{Origin: types.Location{File: "e.go", Line: 1, Function: "E"}, Dropped: true, FailMode: "OPEN"},
		},
		RBACFindings: []types.RBACFinding{
			{Name: "r1", Kind: "ClusterRole", File: "r.yaml", Severity: "HIGH", Rule: "rule", Reason: "reason"},
		},
		TemplateRisks: []types.TemplateRisk{
			{File: "t.yaml", Line: 1, Kind: "SECRET_IN_ARGS", Description: "bad", Severity: "HIGH"},
		},
		RouteCoverage: []types.RouteCoverage{
			{Route: "/admin", RouteKind: "HTTPRoute", Covered: false, RouteFile: "route.yaml"},
		},
		MeshPolicies: []types.MeshPolicyInfo{
			{Name: "m1", Kind: "PeerAuthentication", File: "m.yaml", MTLSMode: "PERMISSIVE", Scope: "namespace-wide"},
		},
		SecretExposures: []types.SecretExposure{
			{Location: types.Location{File: "s.go", Line: 1}, Pattern: "ENV_IN_ARGS", Description: "secret leaked"},
		},
		Lifecycles: []types.ResourceLifecycle{
			{Resource: "Deployment", Orphanable: true, Create: &createLoc},
		},
		WebhookDefaults: []types.WebhookDefault{
			{Function: "Default", File: "w.go", Line: 1, FieldsUnset: []string{"securityContext"}},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	results := log.Runs[0].Results
	if len(results) != 11 {
		t.Errorf("results = %d, want 11 (one per finding type)", len(results))
		for i, r := range results {
			t.Logf("  [%d] ruleId=%s pass=%s", i, r.RuleID, r.Properties["trust-flow-analyzer/pass"])
		}
	}

	// Verify all expected rule ID prefixes are present.
	expectedPrefixes := []string{
		"TFA-CONTRADICTION-",
		"TFA-AUTH-PERMISSIVE",
		"TFA-CONTRACT-",
		"TFA-ERROR-DROPPED",
		"TFA-RBAC-",
		"TFA-TEMPLATE-",
		"TFA-ROUTE-UNCOVERED",
		"TFA-MTLS-",
		"TFA-SECRET-",
		"TFA-LIFECYCLE-ORPHANABLE",
		"TFA-WEBHOOK-UNSET",
	}

	for _, prefix := range expectedPrefixes {
		found := false
		for _, r := range results {
			if strings.HasPrefix(r.RuleID, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no result with ruleId prefix %q", prefix)
		}
	}

	// All results should have project property.
	for i, r := range results {
		if r.Properties["trust-flow-analyzer/project"] != "full-test" {
			t.Errorf("results[%d] project = %q, want full-test", i, r.Properties["trust-flow-analyzer/project"])
		}
	}
}

func TestSARIFDroppedErrorsOnly(t *testing.T) {
	// Non-dropped errors should not produce results.
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		ErrorPaths: []types.ErrorPath{
			{Origin: types.Location{File: "a.go", Line: 1, Function: "A"}, Dropped: false, FailMode: "CLOSED"},
			{Origin: types.Location{File: "b.go", Line: 2, Function: "B"}, Dropped: true, FailMode: "OPEN"},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1 (only dropped)", len(log.Runs[0].Results))
	}
	if log.Runs[0].Results[0].RuleID != "TFA-ERROR-DROPPED" {
		t.Errorf("ruleId = %q, want TFA-ERROR-DROPPED", log.Runs[0].Results[0].RuleID)
	}
}

func TestSARIFCoveredRoutesExcluded(t *testing.T) {
	// Covered routes and INTENTIONAL routes should not produce results.
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		RouteCoverage: []types.RouteCoverage{
			{Route: "/covered", Covered: true, Mechanism: "direct"},
			{Route: "/intentional", Covered: false, Mechanism: "INTENTIONAL"},
			{Route: "/uncovered", Covered: false, RouteKind: "HTTPRoute", RouteFile: "r.yaml"},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 1 {
		t.Fatalf("results = %d, want 1 (only uncovered)", len(log.Runs[0].Results))
	}
	if !strings.Contains(log.Runs[0].Results[0].Message.Text, "/uncovered") {
		t.Error("result should mention the uncovered route")
	}
}

func TestSARIFMTLSStrictExcluded(t *testing.T) {
	// STRICT mTLS should not produce results. PERMISSIVE = warning, DISABLE = error.
	var buf bytes.Buffer
	result := &types.AnalysisResult{
		Project: "test",
		MeshPolicies: []types.MeshPolicyInfo{
			{Name: "strict", Kind: "PeerAuthentication", File: "s.yaml", MTLSMode: "STRICT", Scope: "mesh-wide"},
			{Name: "permissive", Kind: "PeerAuthentication", File: "p.yaml", MTLSMode: "PERMISSIVE", Scope: "namespace-wide"},
			{Name: "disabled", Kind: "PeerAuthentication", File: "d.yaml", MTLSMode: "DISABLE", Scope: "workload-specific"},
		},
	}

	if err := WriteSARIF(&buf, result, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var log SARIFLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(log.Runs[0].Results) != 2 {
		t.Fatalf("results = %d, want 2 (PERMISSIVE + DISABLE)", len(log.Runs[0].Results))
	}

	r0 := log.Runs[0].Results[0]
	if r0.RuleID != "TFA-MTLS-PERMISSIVE" {
		t.Errorf("first result ruleId = %q, want TFA-MTLS-PERMISSIVE", r0.RuleID)
	}
	if r0.Level != "warning" {
		t.Errorf("PERMISSIVE level = %q, want warning", r0.Level)
	}

	r1 := log.Runs[0].Results[1]
	if r1.RuleID != "TFA-MTLS-DISABLE" {
		t.Errorf("second result ruleId = %q, want TFA-MTLS-DISABLE", r1.RuleID)
	}
	if r1.Level != "error" {
		t.Errorf("DISABLE level = %q, want error", r1.Level)
	}
}
