package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/output"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/authflow"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/authpolicy"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/contract"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/defaults"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/errorprop"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/lifecycle"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/meshpolicy"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/netpolicy"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/rbacscope"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/secrets"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/template"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/synthesis"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

const usage = `trust-flow-analyzer: deterministic cross-file trust flow extraction

Usage:
  trust-flow-analyzer analyze [flags] <directory>
  trust-flow-analyzer version
  trust-flow-analyzer help

Commands:
  analyze    Run trust flow analysis on a Go project
  version    Print version
  help       Print this help

Flags for analyze:
  -output     Output file path (default: trust-flow-map.md)
  -format     Output format: markdown, json, html (default: markdown)
`

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "analyze":
		if err := runAnalyze(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("trust-flow-analyzer", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	outputPath := fs.String("output", "trust-flow-map.md", "output file path")
	formatFlag := fs.String("format", "markdown", "output format")
	archContextFlag := fs.String("arch-context", "", "path to architecture-analyzer output (optional)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate format flag.
	switch *formatFlag {
	case "markdown", "json", "html":
		// supported
	default:
		fmt.Fprintf(os.Stderr, "warning: format %q is not supported, defaulting to markdown\n", *formatFlag)
		*formatFlag = "markdown"
	}
	var archCtx *passes.ArchContext
	if *archContextFlag != "" {
		var err error
		archCtx, err = loadArchContext(*archContextFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to load arch-context from %q: %v\n", *archContextFlag, err)
		} else {
			fmt.Fprintf(os.Stderr, "loaded arch-context: %d components\n", len(archCtx.Components))

			var sources []string
			if archCtx.RBACData != nil {
				sources = append(sources, "RBAC")
			}
			if len(archCtx.NetworkPolicies) > 0 {
				sources = append(sources, "NetworkPolicy")
			}
			if len(archCtx.SecurityAnnotations) > 0 {
				sources = append(sources, "security findings")
			}
			if len(sources) > 0 {
				fmt.Fprintf(os.Stderr, "using arch-context for %s\n", strings.Join(sources, ", "))
			}
		}
	}

	if fs.NArg() == 0 {
		return fmt.Errorf("directory argument required")
	}

	dir := fs.Arg(0)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolving directory: %w", err)
	}

	info, err := os.Stat(absDir)
	if err != nil {
		return fmt.Errorf("accessing directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", absDir)
	}

	fmt.Fprintf(os.Stderr, "loading project from %s...\n", absDir)
	prog, err := loader.LoadProject(absDir, os.Stderr)
	if err != nil {
		return fmt.Errorf("loading program: %w", err)
	}
	fmt.Fprintf(os.Stderr, "detected language: %s\n", prog.Language)

	plat := platform.NewKnowledge()
	result := &types.AnalysisResult{
		Project:          filepath.Base(absDir),
		AuthFlows:        []types.AuthFlow{},
		Defaults:         []types.DefaultValue{},
		Contracts:        []types.Contract{},
		ErrorPaths:       []types.ErrorPath{},
		Lifecycles:       []types.ResourceLifecycle{},
		SecretExposures:  []types.SecretExposure{},
		AuthPolicies:     []types.AuthPolicyInfo{},
		RouteCoverage:    []types.RouteCoverage{},
		NetworkPolicies:  []types.NetworkPolicyInfo{},
		RBACFindings:     []types.RBACFinding{},
		MeshPolicies:     []types.MeshPolicyInfo{},
		TemplateRisks:    []types.TemplateRisk{},
		WebhookDefaults:  []types.WebhookDefault{},
		Contradictions:   []types.Contradiction{},
	}

	ctx := &passes.Context{
		Program:     prog,
		Platform:    plat,
		Result:      result,
		ArchContext: archCtx,
	}

	allPasses := []passes.Pass{
		&authflow.Pass{},
		&defaults.Pass{},
		&contract.Pass{},
		&errorprop.Pass{},
		&lifecycle.Pass{},
		&secrets.Pass{},
		&authpolicy.Pass{},
		&netpolicy.Pass{},
		&rbacscope.Pass{},
		&meshpolicy.Pass{},
		&template.Pass{},
	}

	for _, p := range allPasses {
		fmt.Fprintf(os.Stderr, "running %s pass...\n", p.Name())
		if err := p.Run(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s pass failed: %v\n", p.Name(), err)
		}
	}

	fmt.Fprintf(os.Stderr, "synthesizing contradictions...\n")
	synthesis.Synthesize(result)

	// Write to a temp file first, then rename on success to avoid leaving a
	// partial output file if the analysis or write fails.
	// Use the output directory if it exists, otherwise fall back to os.TempDir().
	// When os.TempDir() is used as fallback, os.Rename may fail across
	// filesystem boundaries, but this is preferable to a CreateTemp failure.
	tmpDir := filepath.Dir(*outputPath)
	if info, statErr := os.Stat(tmpDir); statErr != nil || !info.IsDir() {
		tmpDir = os.TempDir()
	}
	tmpFile, err := os.CreateTemp(tmpDir, ".trust-flow-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	var writeErr error
	switch *formatFlag {
	case "json":
		writeErr = output.WriteJSON(tmpFile, result)
	case "html":
		writeErr = output.WriteHTML(tmpFile, result)
	default:
		writeErr = output.WriteMarkdown(tmpFile, result)
	}
	closeErr := tmpFile.Close()

	if writeErr != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("writing output: %w", writeErr)
	}
	if closeErr != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("closing output file: %w", closeErr)
	}

	if err := os.Rename(tmpPath, *outputPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming output file: %w", err)
	}

	fmt.Fprintf(os.Stderr, "wrote %s\n", *outputPath)
	printSummary(os.Stderr, result)

	return nil
}

// loadArchContext reads and parses an architecture-analyzer JSON output file.
// It accepts either a full component-architecture.json (with rbac, network_policies,
// security_annotations, deployments), a minimal object with a "components" field,
// or a bare array of components.
func loadArchContext(path string) (*passes.ArchContext, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Try parsing as a full arch-context object first. json.Unmarshal ignores
	// unknown fields, so this handles both full component-architecture.json and
	// minimal {"components": [...]} formats.
	var archCtx passes.ArchContext
	if err := json.Unmarshal(data, &archCtx); err == nil {
		return &archCtx, nil
	}

	// Fall back to parsing as a bare array of components.
	var components []passes.ArchComponent
	if err := json.Unmarshal(data, &components); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &passes.ArchContext{Components: components}, nil
}

func printSummary(w io.Writer, result *types.AnalysisResult) {
	fmt.Fprintf(w, "\nsummary:\n")
	fmt.Fprintf(w, "  auth flows:        %d\n", len(result.AuthFlows))
	fmt.Fprintf(w, "  config defaults:   %d\n", len(result.Defaults))
	fmt.Fprintf(w, "  contracts:         %d\n", len(result.Contracts))
	fmt.Fprintf(w, "  error paths:       %d\n", len(result.ErrorPaths))
	fmt.Fprintf(w, "  lifecycles:        %d\n", len(result.Lifecycles))
	fmt.Fprintf(w, "  secret exposures:  %d\n", len(result.SecretExposures))
	fmt.Fprintf(w, "  auth policies:     %d\n", len(result.AuthPolicies))
	fmt.Fprintf(w, "  route coverage:    %d\n", len(result.RouteCoverage))
	fmt.Fprintf(w, "  network policies:  %d\n", len(result.NetworkPolicies))
	fmt.Fprintf(w, "  RBAC findings:     %d\n", len(result.RBACFindings))
	fmt.Fprintf(w, "  mesh policies:     %d\n", len(result.MeshPolicies))
	fmt.Fprintf(w, "  template risks:    %d\n", len(result.TemplateRisks))
	fmt.Fprintf(w, "  webhook defaults:  %d\n", len(result.WebhookDefaults))
	fmt.Fprintf(w, "  contradictions:    %d\n", len(result.Contradictions))
}
