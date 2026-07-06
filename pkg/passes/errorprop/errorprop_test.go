package errorprop

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

func TestErrorCreationFound(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(ctx.Result.ErrorPaths) == 0 {
		t.Fatal("expected at least one error path, got 0")
	}

	// ValidateToken creates an error via errors.New("empty token")
	foundValidateToken := false
	for _, ep := range ctx.Result.ErrorPaths {
		if ep.Origin.Function == "ValidateToken" {
			foundValidateToken = true
			break
		}
	}
	if !foundValidateToken {
		t.Error("error creation in ValidateToken not detected")
	}
}

func TestErrorHandled(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The error from errors.New in ValidateToken is returned (not dropped).
	for _, ep := range ctx.Result.ErrorPaths {
		if ep.Origin.Function == "ValidateToken" {
			if ep.Dropped {
				t.Error("ValidateToken error should not be classified as Dropped (it is returned)")
			}

			// Should have at least one RETURN handler
			foundReturn := false
			for _, h := range ep.Handlers {
				if h.Kind == "RETURN" {
					foundReturn = true
					break
				}
			}
			if !foundReturn {
				t.Error("expected RETURN handler for ValidateToken error")
			}
			return
		}
	}
	t.Error("ValidateToken error path not found")
}

func TestFailModeClosed(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, ep := range ctx.Result.ErrorPaths {
		if ep.Origin.Function == "ValidateToken" {
			if ep.FailMode != "CLOSED" {
				t.Errorf("ValidateToken fail mode = %q, want CLOSED", ep.FailMode)
			}
			return
		}
	}
	t.Error("ValidateToken error path not found")
}

func TestPassName(t *testing.T) {
	p := &Pass{}
	if p.Name() != "errorprop" {
		t.Errorf("Name() = %q, want errorprop", p.Name())
	}
}
