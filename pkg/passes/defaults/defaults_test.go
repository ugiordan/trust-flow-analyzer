package defaults

import (
	"os"
	"path/filepath"
	"strings"
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

func TestDefaultsDetected(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(ctx.Result.Defaults) == 0 {
		t.Fatal("expected at least one default value, got 0")
	}

	// The defaults pass uses type-qualified field names (e.g.
	// "example.com/basic/config.Config.AllowedGroups") when the struct type
	// is resolved. Find defaults by suffix matching on the field name.
	ag := findDefaultBySuffix(t, ctx.Result.Defaults, "AllowedGroups")
	if ag == nil {
		t.Fatal("AllowedGroups not detected; found fields:", fieldNames(ctx.Result.Defaults))
	}
	if ag.Permissiveness != "PERMISSIVE" {
		t.Errorf("AllowedGroups permissiveness = %q, want PERMISSIVE", ag.Permissiveness)
	}
	if ag.PlatformMeaning == "" {
		t.Error("AllowedGroups PlatformMeaning is empty, expected platform knowledge")
	}

	// EmailDomain should be detected from DefaultConfig()
	ed := findDefaultBySuffix(t, ctx.Result.Defaults, "EmailDomain")
	if ed == nil {
		t.Fatal("EmailDomain not detected; found fields:", fieldNames(ctx.Result.Defaults))
	}
	if ed.Permissiveness != "PERMISSIVE" {
		t.Errorf("EmailDomain permissiveness = %q, want PERMISSIVE", ed.Permissiveness)
	}
	if ed.PlatformMeaning == "" {
		t.Error("EmailDomain PlatformMeaning is empty, expected platform knowledge")
	}
}

func TestDefaultsPermissive(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, d := range ctx.Result.Defaults {
		if strings.HasSuffix(d.Field, "AllowedGroups") || strings.HasSuffix(d.Field, "EmailDomain") {
			if d.Permissiveness != "PERMISSIVE" {
				t.Errorf("%s permissiveness = %q, want PERMISSIVE", d.Field, d.Permissiveness)
			}
		}
	}
}

func TestPassName(t *testing.T) {
	p := &Pass{}
	if p.Name() != "defaults" {
		t.Errorf("Name() = %q, want defaults", p.Name())
	}
}

// findDefaultBySuffix finds a default value whose Field ends with the given suffix.
func findDefaultBySuffix(t *testing.T, defaults []types.DefaultValue, suffix string) *types.DefaultValue {
	t.Helper()
	for i := range defaults {
		if strings.HasSuffix(defaults[i].Field, suffix) {
			return &defaults[i]
		}
	}
	return nil
}

func fieldNames(defaults []types.DefaultValue) []string {
	var names []string
	for _, d := range defaults {
		names = append(names, d.Field)
	}
	return names
}
