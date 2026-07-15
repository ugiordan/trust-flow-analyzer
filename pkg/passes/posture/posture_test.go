package posture

import (
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestPassName(t *testing.T) {
	p := &Pass{}
	if p.Name() != "posture" {
		t.Errorf("Name() = %q, want posture", p.Name())
	}
}

func TestEmptyResultAllNA(t *testing.T) {
	result := &types.AnalysisResult{Project: "test"}
	ctx := &passes.Context{
		Platform: platform.NewKnowledge(),
		Result:   result,
	}

	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(result.PostureChecks) != 9 {
		t.Fatalf("expected 9 posture checks, got %d", len(result.PostureChecks))
	}

	// With no data, most checks should be N/A or PASS.
	for _, check := range result.PostureChecks {
		if check.Status == "" {
			t.Errorf("check %q has empty status", check.Name)
		}
	}
}

func TestRBACCheckFail(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		RBACFindings: []types.RBACFinding{
			{
				Name:     "cluster-admin",
				Kind:     "ClusterRole",
				Severity: "HIGH",
				Rule:     "secrets CRUD",
				Reason:   "cluster-wide secrets access",
			},
		},
	}
	ctx := &passes.Context{
		Platform: platform.NewKnowledge(),
		Result:   result,
	}

	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	rbacCheck := findCheck(result.PostureChecks, "RBAC scope")
	if rbacCheck == nil {
		t.Fatal("RBAC scope check not found")
	}
	if rbacCheck.Status != "FAIL" {
		t.Errorf("RBAC scope status = %q, want FAIL", rbacCheck.Status)
	}
	if rbacCheck.Severity != "HIGH" {
		t.Errorf("RBAC scope severity = %q, want HIGH", rbacCheck.Severity)
	}
}

func TestMTLSCheckPass(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		MeshPolicies: []types.MeshPolicyInfo{
			{Name: "default", Kind: "PeerAuthentication", MTLSMode: "STRICT"},
		},
	}
	ctx := &passes.Context{
		Platform: platform.NewKnowledge(),
		Result:   result,
	}

	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	mtlsCheck := findCheck(result.PostureChecks, "mTLS mode")
	if mtlsCheck == nil {
		t.Fatal("mTLS mode check not found")
	}
	if mtlsCheck.Status != "PASS" {
		t.Errorf("mTLS mode status = %q, want PASS", mtlsCheck.Status)
	}
}

func TestSecretManagementFail(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		TemplateRisks: []types.TemplateRisk{
			{Kind: "SECRET_IN_ARGS", Field: "$(DB_PASSWORD)", Severity: "HIGH"},
		},
	}
	ctx := &passes.Context{
		Platform: platform.NewKnowledge(),
		Result:   result,
	}

	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	secretCheck := findCheck(result.PostureChecks, "Secret management")
	if secretCheck == nil {
		t.Fatal("Secret management check not found")
	}
	if secretCheck.Status != "FAIL" {
		t.Errorf("Secret management status = %q, want FAIL", secretCheck.Status)
	}
}

func TestResourceLifecyclePass(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		Lifecycles: []types.ResourceLifecycle{
			{
				Resource:   "ConfigMap",
				Create:     &types.Location{File: "ctrl.go", Function: "Reconcile"},
				Owner:      &types.Location{File: "ctrl.go", Function: "Reconcile"},
				Orphanable: false,
			},
		},
	}
	ctx := &passes.Context{
		Platform: platform.NewKnowledge(),
		Result:   result,
	}

	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	lcCheck := findCheck(result.PostureChecks, "Resource lifecycle")
	if lcCheck == nil {
		t.Fatal("Resource lifecycle check not found")
	}
	if lcCheck.Status != "PASS" {
		t.Errorf("Resource lifecycle status = %q, want PASS", lcCheck.Status)
	}
}

func TestScore(t *testing.T) {
	checks := []types.PostureCheck{
		{Status: "PASS"},
		{Status: "PASS"},
		{Status: "FAIL"},
		{Status: "PARTIAL"},
		{Status: "N/A"},
	}

	score := Score(checks)
	// 4 applicable: 2 PASS (2.0) + 1 PARTIAL (0.5) + 1 FAIL (0) = 2.5/4 = 62.5%
	if score < 62.4 || score > 62.6 {
		t.Errorf("Score = %.1f%%, want 62.5%%", score)
	}
}

func TestScoreAllNA(t *testing.T) {
	checks := []types.PostureCheck{
		{Status: "N/A"},
		{Status: "N/A"},
	}

	score := Score(checks)
	if score != 100.0 {
		t.Errorf("Score = %.1f%%, want 100.0%%", score)
	}
}

func findCheck(checks []types.PostureCheck, name string) *types.PostureCheck {
	for i := range checks {
		if checks[i].Name == name {
			return &checks[i]
		}
	}
	return nil
}
