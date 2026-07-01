package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

func TestWriteMarkdownEmpty(t *testing.T) {
	var buf bytes.Buffer
	result := &types.AnalysisResult{Project: "test-project"}

	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "# Trust Flow Map: test-project") {
		t.Error("missing project header")
	}
}

func TestWriteMarkdownAuthFlows(t *testing.T) {
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

	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	got := buf.String()

	checks := []string{
		"## Authentication Flows",
		"### Path: proxy",
		"Entry: handler.go:ServeHTTP (line 10)",
		"Authentication: auth.go:ValidateToken (line 5)",
		"Authorization: NONE",
		"Combined posture: PERMISSIVE",
	}

	for _, check := range checks {
		if !strings.Contains(got, check) {
			t.Errorf("output missing %q", check)
		}
	}
}

func TestWriteMarkdownDefaults(t *testing.T) {
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

	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "## Configuration Defaults") {
		t.Error("missing defaults section")
	}
	if !strings.Contains(got, "| audiences |") {
		t.Error("missing audiences row")
	}
}

func TestWriteMarkdownContradictions(t *testing.T) {
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

	if err := WriteMarkdown(&buf, result); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	got := buf.String()
	if !strings.Contains(got, "## Assumption Contradictions") {
		t.Error("missing contradictions section")
	}
	if !strings.Contains(got, "CONTRADICTION-001") {
		t.Error("missing contradiction ID")
	}
}
