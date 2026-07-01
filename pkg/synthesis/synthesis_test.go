package synthesis

import (
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestSynthesizeEmpty(t *testing.T) {
	result := &types.AnalysisResult{Project: "test"}
	Synthesize(result)

	if len(result.Contradictions) != 0 {
		t.Errorf("expected 0 contradictions, got %d", len(result.Contradictions))
	}
}

func TestDetectAuthWithoutAuthz(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		AuthFlows: []types.AuthFlow{
			{
				Name:    "proxy",
				Posture: "PERMISSIVE",
				Entry:   types.Location{File: "handler.go", Function: "ServeHTTP"},
				Authentication: &types.AuthStep{
					Location: types.Location{File: "auth.go", Function: "ValidateToken"},
				},
			},
		},
	}

	Synthesize(result)

	if len(result.Contradictions) == 0 {
		t.Fatal("expected at least one contradiction for auth without authz")
	}

	found := false
	for _, c := range result.Contradictions {
		if c.Severity == "HIGH" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected HIGH severity contradiction for auth without authz")
	}
}

func TestDetectPermissiveDefaults(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		Defaults: []types.DefaultValue{
			{Field: "audiences", Permissiveness: "PERMISSIVE", LibraryDefault: "nil", PlatformMeaning: "accept all"},
			{Field: "AllowedGroups", Permissiveness: "PERMISSIVE", LibraryDefault: "nil", PlatformMeaning: "allow all"},
		},
	}

	Synthesize(result)

	found := false
	for _, c := range result.Contradictions {
		if c.Severity == "MEDIUM" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected MEDIUM severity contradiction for multiple permissive defaults")
	}
}

func TestDetectOrphanedResources(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		Lifecycles: []types.ResourceLifecycle{
			{
				Resource:   "ConfigMap",
				Create:     types.Location{File: "ctrl.go", Function: "Reconcile"},
				Orphanable: true,
			},
		},
	}

	Synthesize(result)

	found := false
	for _, c := range result.Contradictions {
		if c.Severity == "LOW" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected LOW severity contradiction for orphaned resource")
	}
}

func TestContradictionIDsAreSequential(t *testing.T) {
	result := &types.AnalysisResult{
		Project: "test",
		AuthFlows: []types.AuthFlow{
			{
				Name:    "a",
				Posture: "PERMISSIVE",
				Entry:   types.Location{File: "a.go", Function: "ServeHTTP"},
				Authentication: &types.AuthStep{
					Location: types.Location{File: "auth.go", Function: "ValidateToken"},
				},
			},
		},
		Lifecycles: []types.ResourceLifecycle{
			{
				Resource:   "Secret",
				Create:     types.Location{File: "ctrl.go", Function: "Reconcile"},
				Orphanable: true,
			},
		},
	}

	Synthesize(result)

	for i, c := range result.Contradictions {
		expected := "CONTRADICTION-"
		if len(c.ID) < len(expected)+3 {
			t.Errorf("contradiction %d has short ID: %q", i, c.ID)
		}
	}
}
