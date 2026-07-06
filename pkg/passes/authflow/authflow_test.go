package authflow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func loadFixture(t *testing.T) *passes.Context {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "testdata", "basic")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	prog, err := loader.LoadGo(absDir, os.Stderr)
	if err != nil {
		t.Fatalf("LoadGo: %v", err)
	}
	return &passes.Context{
		Program:  prog,
		Platform: platform.NewKnowledge(),
		Result:   &types.AnalysisResult{Project: "basic"},
	}
}

func TestAuthFlowCount(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(ctx.Result.AuthFlows) != 2 {
		t.Fatalf("expected 2 auth flows, got %d", len(ctx.Result.AuthFlows))
	}
}

func TestAuthFlowPostures(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	flowsByName := make(map[string]*types.AuthFlow)
	for i := range ctx.Result.AuthFlows {
		flowsByName[ctx.Result.AuthFlows[i].Name] = &ctx.Result.AuthFlows[i]
	}

	// ProxyHandler has both authn (ValidateToken) and authz (Authorize), so RESTRICTIVE
	proxy, ok := flowsByName["handler.ProxyHandler"]
	if !ok {
		t.Fatal("ProxyHandler flow not found; available flows:", flowNames(ctx.Result.AuthFlows))
	}
	if proxy.Posture != "RESTRICTIVE" {
		t.Errorf("ProxyHandler posture = %q, want RESTRICTIVE", proxy.Posture)
	}

	// AdminHandler has only authn (ValidateToken), no authz, so PERMISSIVE
	admin, ok := flowsByName["handler.AdminHandler"]
	if !ok {
		t.Fatal("AdminHandler flow not found; available flows:", flowNames(ctx.Result.AuthFlows))
	}
	if admin.Posture != "PERMISSIVE" {
		t.Errorf("AdminHandler posture = %q, want PERMISSIVE", admin.Posture)
	}
}

func TestProxyHandlerHasBothAuthnAndAuthz(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	proxy := findFlow(t, ctx.Result.AuthFlows, "handler.ProxyHandler")

	if proxy.Authentication == nil {
		t.Fatal("ProxyHandler: authentication step is nil")
	}
	if proxy.Authentication.Location.Function != "ValidateToken" {
		t.Errorf("ProxyHandler authn function = %q, want ValidateToken", proxy.Authentication.Location.Function)
	}

	if proxy.Authorization == nil {
		t.Fatal("ProxyHandler: authorization step is nil")
	}
	if proxy.Authorization.Location.Function != "Authorize" {
		t.Errorf("ProxyHandler authz function = %q, want Authorize", proxy.Authorization.Location.Function)
	}
}

func TestAdminHandlerHasAuthnButNoAuthz(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	admin := findFlow(t, ctx.Result.AuthFlows, "handler.AdminHandler")

	if admin.Authentication == nil {
		t.Fatal("AdminHandler: authentication step is nil")
	}
	if admin.Authentication.Location.Function != "ValidateToken" {
		t.Errorf("AdminHandler authn function = %q, want ValidateToken", admin.Authentication.Location.Function)
	}

	if admin.Authorization != nil {
		t.Errorf("AdminHandler: expected no authorization, got %q", admin.Authorization.Location.Function)
	}
}

func TestAuthFunctionClassification(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// ValidateToken is authn: should appear as Authentication.Location.Function
	proxy := findFlow(t, ctx.Result.AuthFlows, "handler.ProxyHandler")
	if proxy.Authentication == nil || proxy.Authentication.Location.Function != "ValidateToken" {
		t.Error("ValidateToken not detected as authn")
	}

	// Authorize is authz: should appear as Authorization.Location.Function
	if proxy.Authorization == nil || proxy.Authorization.Location.Function != "Authorize" {
		t.Error("Authorize not detected as authz")
	}

	// ValidateToken is also classified as authn in AdminHandler
	admin := findFlow(t, ctx.Result.AuthFlows, "handler.AdminHandler")
	if admin.Authentication == nil || admin.Authentication.Location.Function != "ValidateToken" {
		t.Error("ValidateToken not detected as authn in AdminHandler")
	}
}

func TestCheckGroupsClassification(t *testing.T) {
	// CheckGroups is classified as a "validator" pattern. However, it is not
	// called from either handler in the basic fixture. The authflow pass only
	// includes auth functions reachable from entry points. Verify that CheckGroups
	// does NOT appear in any flow (since it is unreachable from the handlers).
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, flow := range ctx.Result.AuthFlows {
		for _, v := range flow.Validators {
			if v.Location.Function == "CheckGroups" {
				// CheckGroups is not called from any handler in the fixture,
				// so it should not be reachable. If the fixture is updated
				// to call CheckGroups, this test should be updated accordingly.
				t.Errorf("CheckGroups found as validator in flow %q, but it is not called from any handler", flow.Name)
			}
		}
	}
}

func TestEntryPointsAreServeHTTP(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, flow := range ctx.Result.AuthFlows {
		if flow.Entry.Function != "ServeHTTP" {
			t.Errorf("flow %q entry function = %q, want ServeHTTP", flow.Name, flow.Entry.Function)
		}
	}
}

func TestPassName(t *testing.T) {
	p := &Pass{}
	if p.Name() != "authflow" {
		t.Errorf("Name() = %q, want authflow", p.Name())
	}
}

// findFlow locates a flow by name or fails the test.
func findFlow(t *testing.T, flows []types.AuthFlow, name string) *types.AuthFlow {
	t.Helper()
	for i := range flows {
		if flows[i].Name == name {
			return &flows[i]
		}
	}
	t.Fatalf("flow %q not found; available: %v", name, flowNames(flows))
	return nil
}

func flowNames(flows []types.AuthFlow) []string {
	var names []string
	for _, f := range flows {
		names = append(names, f.Name)
	}
	return names
}
