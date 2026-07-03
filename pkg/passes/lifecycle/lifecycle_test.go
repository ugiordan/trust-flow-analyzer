package lifecycle

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
	prog, err := loader.Load(absDir, os.Stderr)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return &passes.Context{
		Program:  prog,
		Platform: platform.NewKnowledge(),
		Result:   &types.AnalysisResult{Project: "basic"},
	}
}

func TestNoLifecycleEntries(t *testing.T) {
	ctx := loadFixture(t)
	p := &Pass{}
	if err := p.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The basic fixture has no K8s client calls (no Create, Delete,
	// SetOwnerReference, AddFinalizer, etc.), so no lifecycle entries
	// should be found.
	if len(ctx.Result.Lifecycles) != 0 {
		t.Errorf("expected 0 lifecycle entries, got %d", len(ctx.Result.Lifecycles))
		for _, lc := range ctx.Result.Lifecycles {
			t.Logf("  resource=%s create=%v delete=%v owner=%v finalizer=%v orphanable=%v",
				lc.Resource,
				lc.Create != nil,
				lc.Delete != nil,
				lc.Owner != nil,
				lc.Finalizer != nil,
				lc.Orphanable,
			)
		}
	}
}

func TestPassName(t *testing.T) {
	p := &Pass{}
	if p.Name() != "lifecycle" {
		t.Errorf("Name() = %q, want lifecycle", p.Name())
	}
}
