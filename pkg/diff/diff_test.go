package diff

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestCompareIdentical(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "mTLS mismatch", Severity: "HIGH",
				Assumptions: []types.Assumption{{Location: types.Location{File: "a.go", Line: 1}}}},
		},
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Rule: "wildcard", Severity: "HIGH", File: "rbac.yaml", Reason: "wildcard verbs"},
		},
	}

	d := Compare(result, result)

	if len(d.New) != 0 {
		t.Errorf("new = %d, want 0", len(d.New))
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %d, want 0", len(d.Removed))
	}
	if len(d.Changed) != 0 {
		t.Errorf("changed = %d, want 0", len(d.Changed))
	}
	if d.Unchanged != 2 {
		t.Errorf("unchanged = %d, want 2", d.Unchanged)
	}
	if d.HasNew() {
		t.Error("HasNew() = true, want false for identical results")
	}
}

func TestCompareNewFinding(t *testing.T) {
	baseline := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "existing contradiction", Severity: "MEDIUM"},
		},
	}

	current := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "existing contradiction", Severity: "MEDIUM"},
			{ID: "C-002", Title: "new contradiction", Severity: "HIGH",
				Assumptions: []types.Assumption{{Location: types.Location{File: "b.go", Line: 10}}}},
		},
	}

	d := Compare(baseline, current)

	if len(d.New) != 1 {
		t.Fatalf("new = %d, want 1", len(d.New))
	}
	if d.New[0].Category != "contradiction" {
		t.Errorf("new[0].Category = %q, want contradiction", d.New[0].Category)
	}
	if !strings.Contains(d.New[0].Summary, "new contradiction") {
		t.Errorf("new[0].Summary = %q, should contain 'new contradiction'", d.New[0].Summary)
	}
	if d.New[0].Severity != "HIGH" {
		t.Errorf("new[0].Severity = %q, want HIGH", d.New[0].Severity)
	}
	if d.New[0].File != "b.go" {
		t.Errorf("new[0].File = %q, want b.go", d.New[0].File)
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if !d.HasNew() {
		t.Error("HasNew() = false, want true when new findings exist")
	}
}

func TestCompareRemovedFinding(t *testing.T) {
	baseline := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Rule: "wildcard", Severity: "HIGH", File: "rbac.yaml", Reason: "wildcard verbs"},
			{Name: "viewer", Rule: "secrets", Severity: "MEDIUM", File: "rbac.yaml", Reason: "read secrets"},
		},
	}

	current := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Rule: "wildcard", Severity: "HIGH", File: "rbac.yaml", Reason: "wildcard verbs"},
		},
	}

	d := Compare(baseline, current)

	if len(d.New) != 0 {
		t.Errorf("new = %d, want 0", len(d.New))
	}
	if len(d.Removed) != 1 {
		t.Fatalf("removed = %d, want 1", len(d.Removed))
	}
	if d.Removed[0].Category != "rbac" {
		t.Errorf("removed[0].Category = %q, want rbac", d.Removed[0].Category)
	}
	if !strings.Contains(d.Removed[0].Key, "viewer") {
		t.Errorf("removed[0].Key = %q, should contain 'viewer'", d.Removed[0].Key)
	}
	if d.Unchanged != 1 {
		t.Errorf("unchanged = %d, want 1", d.Unchanged)
	}
	if d.HasNew() {
		t.Error("HasNew() = true, want false when only removals")
	}
}

func TestCompareChangedSeverity(t *testing.T) {
	baseline := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "some contradiction", Severity: "MEDIUM",
				Assumptions: []types.Assumption{{Location: types.Location{File: "a.go", Line: 5}}}},
		},
	}

	current := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "some contradiction", Severity: "HIGH",
				Assumptions: []types.Assumption{{Location: types.Location{File: "a.go", Line: 5}}}},
		},
	}

	d := Compare(baseline, current)

	if len(d.New) != 0 {
		t.Errorf("new = %d, want 0", len(d.New))
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %d, want 0", len(d.Removed))
	}
	if len(d.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(d.Changed))
	}
	if d.Changed[0].OldSeverity != "MEDIUM" {
		t.Errorf("oldSeverity = %q, want MEDIUM", d.Changed[0].OldSeverity)
	}
	if d.Changed[0].NewSeverity != "HIGH" {
		t.Errorf("newSeverity = %q, want HIGH", d.Changed[0].NewSeverity)
	}
	if d.Unchanged != 0 {
		t.Errorf("unchanged = %d, want 0", d.Unchanged)
	}
	if !d.HasNew() {
		t.Error("HasNew() = false, want true when severity worsened")
	}
}

func TestCompareChangedSeverityDowngrade(t *testing.T) {
	baseline := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "some contradiction", Severity: "HIGH"},
		},
	}

	current := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-001", Title: "some contradiction", Severity: "LOW"},
		},
	}

	d := Compare(baseline, current)

	if len(d.Changed) != 1 {
		t.Fatalf("changed = %d, want 1", len(d.Changed))
	}
	// Downgrade should not count as "new"
	if d.HasNew() {
		t.Error("HasNew() = true, want false for severity downgrade")
	}
}

func TestCompareEmpty(t *testing.T) {
	empty := &types.AnalysisResult{Project: "empty"}

	d := Compare(empty, empty)

	if len(d.New) != 0 {
		t.Errorf("new = %d, want 0", len(d.New))
	}
	if len(d.Removed) != 0 {
		t.Errorf("removed = %d, want 0", len(d.Removed))
	}
	if len(d.Changed) != 0 {
		t.Errorf("changed = %d, want 0", len(d.Changed))
	}
	if d.Unchanged != 0 {
		t.Errorf("unchanged = %d, want 0", d.Unchanged)
	}
	if d.HasNew() {
		t.Error("HasNew() = true, want false for empty results")
	}
}

func TestFlatten(t *testing.T) {
	createLoc := types.Location{File: "create.go", Line: 5, Function: "Create"}
	result := &types.AnalysisResult{
		Project: "test",
		Contradictions: []types.Contradiction{
			{ID: "C-1", Title: "mTLS gap", Severity: "HIGH",
				Assumptions: []types.Assumption{{Location: types.Location{File: "a.go", Line: 1}}}},
		},
		AuthFlows: []types.AuthFlow{
			{Name: "proxy", Entry: types.Location{File: "h.go", Line: 10}, Posture: "PERMISSIVE"},
			{Name: "internal", Entry: types.Location{File: "i.go", Line: 5}, Posture: "RESTRICTIVE"},
		},
		Contracts: []types.Contract{
			{Function: types.Location{File: "c.go", Line: 1, Function: "Validate"},
				Violations: []types.ContractViolation{
					{Caller: types.Location{File: "d.go", Line: 2, Function: "Handle"}, Kind: "UNCHECKED_ERROR", Description: "err dropped"},
				}},
		},
		ErrorPaths: []types.ErrorPath{
			{Origin: types.Location{File: "e.go", Line: 1, Function: "Init"}, Dropped: true, FailMode: "OPEN"},
			{Origin: types.Location{File: "e2.go", Line: 2, Function: "Run"}, Dropped: false, FailMode: "CLOSED"},
		},
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Rule: "wildcard", Severity: "HIGH", File: "rbac.yaml", Reason: "wildcard verbs"},
		},
		TemplateRisks: []types.TemplateRisk{
			{File: "t.yaml", Line: 10, Kind: "SECRET_IN_ARGS", Description: "secret in args", Severity: "HIGH"},
		},
		RouteCoverage: []types.RouteCoverage{
			{Route: "/admin", RouteKind: "HTTPRoute", Covered: false, RouteFile: "route.yaml"},
			{Route: "/health", RouteKind: "HTTPRoute", Covered: true},
			{Route: "/metrics", RouteKind: "HTTPRoute", Covered: false, Mechanism: "INTENTIONAL"},
		},
		MeshPolicies: []types.MeshPolicyInfo{
			{Name: "default", Kind: "PeerAuthentication", File: "mesh.yaml", MTLSMode: "PERMISSIVE", Scope: "namespace-wide"},
			{Name: "strict", Kind: "PeerAuthentication", File: "mesh2.yaml", MTLSMode: "STRICT", Scope: "mesh-wide"},
		},
		SecretExposures: []types.SecretExposure{
			{Location: types.Location{File: "s.go", Line: 3}, Pattern: "ENV_IN_ARGS", Description: "secret leaked"},
		},
		Lifecycles: []types.ResourceLifecycle{
			{Resource: "ConfigMap", Orphanable: true, Create: &createLoc},
			{Resource: "Deployment", Orphanable: false},
		},
		WebhookDefaults: []types.WebhookDefault{
			{Function: "Default", File: "w.go", Line: 1, FieldsUnset: []string{"securityContext"}},
			{Function: "Other", File: "w2.go", Line: 5, FieldsUnset: nil},
		},
	}

	findings := Flatten(result)

	// Count expected findings:
	// 1 contradiction + 1 permissive authflow + 1 contract violation +
	// 1 dropped error + 1 rbac + 1 template + 1 uncovered route +
	// 1 weak mtls + 1 secret + 1 orphanable lifecycle + 1 webhook = 11
	if len(findings) != 11 {
		t.Errorf("flatten produced %d findings, want 11", len(findings))
		for i, f := range findings {
			t.Logf("  [%d] %s: %s (key=%s)", i, f.Category, f.Summary, f.Key)
		}
	}

	// Verify categories present
	categories := make(map[string]int)
	for _, f := range findings {
		categories[f.Category]++
	}

	expected := map[string]int{
		"contradiction": 1,
		"authflow":      1,
		"contract":      1,
		"error":         1,
		"rbac":          1,
		"template":      1,
		"route":         1,
		"mtls":          1,
		"secret":        1,
		"lifecycle":     1,
		"webhook":       1,
	}

	for cat, count := range expected {
		if categories[cat] != count {
			t.Errorf("category %q: got %d findings, want %d", cat, categories[cat], count)
		}
	}
}

func TestFlattenEmpty(t *testing.T) {
	result := &types.AnalysisResult{Project: "empty"}
	findings := Flatten(result)

	if len(findings) != 0 {
		t.Errorf("flatten on empty result produced %d findings, want 0", len(findings))
	}
}

func TestFlattenStableKeys(t *testing.T) {
	// Verify that keys are deterministic across multiple calls.
	result := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{Name: "admin", Rule: "wildcard", Severity: "HIGH", File: "rbac.yaml", Reason: "wildcard verbs"},
		},
	}

	f1 := Flatten(result)
	f2 := Flatten(result)

	if len(f1) != len(f2) {
		t.Fatalf("different lengths: %d vs %d", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].Key != f2[i].Key {
			t.Errorf("keys differ at index %d: %q vs %q", i, f1[i].Key, f2[i].Key)
		}
	}
}

func TestWriteText(t *testing.T) {
	d := &DiffResult{
		New: []DiffFinding{
			{Category: "rbac", Key: "rbac:admin:wildcard", Summary: "cluster-wide secrets CRUD", Severity: "HIGH", File: "rbac.yaml"},
			{Category: "route", Key: "route:/admin", Summary: "/admin has no auth policy coverage", Severity: "MEDIUM"},
		},
		Removed: []DiffFinding{
			{Category: "template", Key: "template:deploy.yaml:45:SECRET_IN_ARGS", Summary: "secret expanded in container args", Severity: "MEDIUM", File: "deploy.yaml", Line: 45},
		},
		Changed: []DiffChange{
			{Finding: DiffFinding{Category: "contract", Summary: "unchecked error from ValidateToken"}, OldSeverity: "MEDIUM", NewSeverity: "HIGH"},
		},
		Unchanged: 10,
	}

	var buf bytes.Buffer
	if err := WriteText(&buf, d); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}

	out := buf.String()

	if !strings.Contains(out, "New findings (2)") {
		t.Error("missing new findings header")
	}
	if !strings.Contains(out, "[HIGH] Rbac: cluster-wide secrets CRUD") {
		t.Error("missing HIGH rbac finding")
	}
	if !strings.Contains(out, "Removed findings (1)") {
		t.Error("missing removed findings header")
	}
	if !strings.Contains(out, "(fixed)") {
		t.Error("missing (fixed) suffix on removed findings")
	}
	if !strings.Contains(out, "Changed severity (1)") {
		t.Error("missing changed severity header")
	}
	if !strings.Contains(out, "MEDIUM -> HIGH") {
		t.Error("missing severity change")
	}
	// Baseline: removed(1) + unchanged(10) + changed(1) = 12
	// Current: new(2) + unchanged(10) + changed(1) = 13
	if !strings.Contains(out, "Baseline: 12") {
		t.Errorf("wrong baseline count, output: %s", out)
	}
	if !strings.Contains(out, "Current: 13") {
		t.Errorf("wrong current count, output: %s", out)
	}
}

func TestWriteTextEmpty(t *testing.T) {
	d := &DiffResult{}

	var buf bytes.Buffer
	if err := WriteText(&buf, d); err != nil {
		t.Fatalf("WriteText failed: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "New findings (0)") {
		t.Error("missing empty new findings header")
	}
	if !strings.Contains(out, "None") {
		t.Error("missing 'None' for empty sections")
	}
}

func TestWriteJSON(t *testing.T) {
	d := &DiffResult{
		New: []DiffFinding{
			{Category: "rbac", Key: "rbac:admin:wildcard", Summary: "test", Severity: "HIGH"},
		},
		Unchanged: 5,
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, d); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	var out DiffJSON
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if len(out.New) != 1 {
		t.Errorf("new = %d, want 1", len(out.New))
	}
	if len(out.Removed) != 0 {
		t.Errorf("removed = %d, want 0 (should be empty array, not null)", len(out.Removed))
	}
	if out.Unchanged != 5 {
		t.Errorf("unchanged = %d, want 5", out.Unchanged)
	}
	if out.Summary.NewCount != 1 {
		t.Errorf("summary.new_count = %d, want 1", out.Summary.NewCount)
	}
}

func TestWriteSARIF(t *testing.T) {
	d := &DiffResult{
		New: []DiffFinding{
			{Category: "rbac", Key: "rbac:admin:wildcard", Summary: "test finding", Severity: "HIGH", File: "rbac.yaml"},
			{Category: "route", Key: "route:/admin", Summary: "uncovered route", Severity: "MEDIUM"},
		},
	}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, d, "1.0.0"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	// Verify valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `"version": "2.1.0"`) {
		t.Error("missing SARIF version")
	}
	if !strings.Contains(out, "trust-flow-analyzer-diff") {
		t.Error("missing tool name")
	}
	if !strings.Contains(out, "test finding") {
		t.Error("missing finding message")
	}
	if !strings.Contains(out, "TFA-DIFF-NEW-RBAC") {
		t.Error("missing diff rule ID for RBAC")
	}
}

func TestWriteSARIFEmpty(t *testing.T) {
	d := &DiffResult{}

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, d, "dev"); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
}
