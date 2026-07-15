package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/config"
	"github.com/ugiordan/trust-flow-analyzer/pkg/diff"
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
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/posture"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/secrets"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes/template"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/synthesis"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

const usage = `trust-flow-analyzer: deterministic cross-file trust flow extraction

Usage:
  trust-flow-analyzer analyze [flags] <directory>
  trust-flow-analyzer diff [flags] <baseline.json> <current.json>
  trust-flow-analyzer version
  trust-flow-analyzer help

Commands:
  analyze    Run trust flow analysis on a Go project
  diff       Compare two analysis outputs and report changes
  version    Print version
  help       Print this help

Flags for analyze:
  -output     Output file path (default: trust-flow-map.md)
  -format     Output format: markdown, json, html, sarif (default: markdown)
  -baseline   Path to baseline JSON to diff against (outputs only new/worsened findings)
  -config     Path to YAML config file with custom rules (optional)

Flags for diff:
  -format     Output format: text, json, sarif (default: text)
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
	case "diff":
		if err := runDiff(os.Args[2:]); err != nil {
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
	baselineFlag := fs.String("baseline", "", "path to baseline JSON to diff against (outputs only new/worsened findings)")
	configFlag := fs.String("config", "", "path to YAML config file with custom rules (optional)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Validate format flag.
	switch *formatFlag {
	case "markdown", "json", "html", "sarif":
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

	// Load custom config if provided.
	var userConfig *config.Config
	if *configFlag != "" {
		var cfgErr error
		userConfig, cfgErr = config.LoadConfig(*configFlag)
		if cfgErr != nil {
			return fmt.Errorf("loading config from %q: %w", *configFlag, cfgErr)
		}
		fmt.Fprintf(os.Stderr, "loaded config: %d platform_knowledge, %d auth_patterns, %d entry_points, %d security_fields, %d skip_dirs\n",
			len(userConfig.PlatformKnowledge), len(userConfig.AuthPatterns), len(userConfig.EntryPoints),
			len(userConfig.SecurityFields), len(userConfig.SkipDirs))
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

	// Merge custom skip dirs into the loader before loading the project.
	if userConfig != nil && len(userConfig.SkipDirs) > 0 {
		loader.AddSkipDirs(userConfig.SkipDirs)
		fmt.Fprintf(os.Stderr, "added %d custom skip dirs\n", len(userConfig.SkipDirs))
	}

	fmt.Fprintf(os.Stderr, "loading project from %s...\n", absDir)
	prog, err := loader.LoadProject(absDir, os.Stderr)
	if err != nil {
		return fmt.Errorf("loading program: %w", err)
	}
	fmt.Fprintf(os.Stderr, "detected language: %s\n", prog.Language)

	plat := platform.NewKnowledge()

	// Merge custom platform knowledge into the knowledge base.
	if userConfig != nil {
		for _, pk := range userConfig.PlatformKnowledge {
			plat.AddCustom(pk.Field, platform.FieldSemantics{
				Field:          pk.Field,
				EmptyMeaning:   pk.EmptyMeaning,
				Permissiveness: pk.Permissiveness,
			})
		}
	}
	result := &types.AnalysisResult{
		Project:            filepath.Base(absDir),
		AuthFlows:          []types.AuthFlow{},
		Defaults:           []types.DefaultValue{},
		Contracts:          []types.Contract{},
		ErrorPaths:         []types.ErrorPath{},
		Lifecycles:         []types.ResourceLifecycle{},
		SecretExposures:    []types.SecretExposure{},
		AuthPolicies:       []types.AuthPolicyInfo{},
		RouteCoverage:      []types.RouteCoverage{},
		NetworkPolicies:    []types.NetworkPolicyInfo{},
		RBACFindings:       []types.RBACFinding{},
		MeshPolicies:       []types.MeshPolicyInfo{},
		TemplateRisks:      []types.TemplateRisk{},
		WebhookDefaults:    []types.WebhookDefault{},
		WebhookValidations: []types.WebhookValidation{},
		PostureChecks:      []types.PostureCheck{},
		Contradictions:     []types.Contradiction{},
	}

	ctx := &passes.Context{
		Program:      prog,
		Platform:     plat,
		Result:       result,
		ArchContext:  archCtx,
		CustomConfig: userConfig,
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
	synthesis.Synthesize(result, archCtx)

	// Run posture check AFTER synthesis (it reads contradictions).
	posturePass := &posture.Pass{}
	fmt.Fprintf(os.Stderr, "running %s pass...\n", posturePass.Name())
	if err := posturePass.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s pass failed: %v\n", posturePass.Name(), err)
	}

	// If --baseline is set, diff against it and output only new/worsened findings.
	if *baselineFlag != "" {
		baselineResult, err := loadAnalysisResult(*baselineFlag)
		if err != nil {
			return fmt.Errorf("loading baseline: %w", err)
		}

		diffResult := diff.Compare(baselineResult, result)

		var diffBuf bytes.Buffer
		switch *formatFlag {
		case "json":
			if err := diff.WriteJSON(&diffBuf, diffResult); err != nil {
				return fmt.Errorf("writing diff JSON: %w", err)
			}
		case "sarif":
			if err := diff.WriteSARIF(&diffBuf, diffResult, version); err != nil {
				return fmt.Errorf("writing diff SARIF: %w", err)
			}
		default:
			if err := diff.WriteText(&diffBuf, diffResult); err != nil {
				return fmt.Errorf("writing diff output: %w", err)
			}
		}

		if err := os.WriteFile(*outputPath, diffBuf.Bytes(), 0o644); err != nil {
			return fmt.Errorf("writing diff output file: %w", err)
		}

		fmt.Fprintf(os.Stderr, "wrote diff to %s\n", *outputPath)
		fmt.Fprintf(os.Stderr, "new: %d, removed: %d, changed: %d, unchanged: %d\n",
			len(diffResult.New), len(diffResult.Removed), len(diffResult.Changed), diffResult.Unchanged)

		if diffResult.HasNew() {
			os.Exit(1)
		}
		return nil
	}

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
	case "sarif":
		writeErr = output.WriteSARIF(tmpFile, result, version)
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

func runDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	formatFlag := fs.String("format", "text", "output format: text, json, sarif")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 2 {
		return fmt.Errorf("diff requires two arguments: <baseline.json> <current.json>")
	}

	baselinePath := fs.Arg(0)
	currentPath := fs.Arg(1)

	baseline, err := loadAnalysisResult(baselinePath)
	if err != nil {
		return fmt.Errorf("loading baseline %q: %w", baselinePath, err)
	}

	current, err := loadAnalysisResult(currentPath)
	if err != nil {
		return fmt.Errorf("loading current %q: %w", currentPath, err)
	}

	diffResult := diff.Compare(baseline, current)

	switch *formatFlag {
	case "json":
		if err := diff.WriteJSON(os.Stdout, diffResult); err != nil {
			return fmt.Errorf("writing JSON: %w", err)
		}
	case "sarif":
		if err := diff.WriteSARIF(os.Stdout, diffResult, version); err != nil {
			return fmt.Errorf("writing SARIF: %w", err)
		}
	default:
		if err := diff.WriteText(os.Stdout, diffResult); err != nil {
			return fmt.Errorf("writing output: %w", err)
		}
	}

	if diffResult.HasNew() {
		os.Exit(1)
	}
	return nil
}

// loadAnalysisResult reads and parses a trust-flow-analyzer JSON output file.
func loadAnalysisResult(path string) (*types.AnalysisResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	var result types.AnalysisResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return &result, nil
}

func printSummary(w io.Writer, result *types.AnalysisResult) {
	fmt.Fprintf(w, "\nsummary:\n")
	fmt.Fprintf(w, "  auth flows:          %d\n", len(result.AuthFlows))
	fmt.Fprintf(w, "  config defaults:     %d\n", len(result.Defaults))
	fmt.Fprintf(w, "  contracts:           %d\n", len(result.Contracts))
	fmt.Fprintf(w, "  error paths:         %d\n", len(result.ErrorPaths))
	fmt.Fprintf(w, "  lifecycles:          %d\n", len(result.Lifecycles))
	fmt.Fprintf(w, "  secret exposures:    %d\n", len(result.SecretExposures))
	fmt.Fprintf(w, "  auth policies:       %d\n", len(result.AuthPolicies))
	fmt.Fprintf(w, "  route coverage:      %d\n", len(result.RouteCoverage))
	fmt.Fprintf(w, "  network policies:    %d\n", len(result.NetworkPolicies))
	fmt.Fprintf(w, "  RBAC findings:       %d\n", len(result.RBACFindings))
	fmt.Fprintf(w, "  mesh policies:       %d\n", len(result.MeshPolicies))
	fmt.Fprintf(w, "  template risks:      %d\n", len(result.TemplateRisks))
	fmt.Fprintf(w, "  webhook defaults:    %d\n", len(result.WebhookDefaults))
	fmt.Fprintf(w, "  webhook validations: %d\n", len(result.WebhookValidations))
	fmt.Fprintf(w, "  posture checks:      %d\n", len(result.PostureChecks))
	fmt.Fprintf(w, "  contradictions:      %d\n", len(result.Contradictions))

	if len(result.PostureChecks) > 0 {
		score := postureScore(result.PostureChecks)
		fmt.Fprintf(w, "  posture score:       %.0f%%\n", score)
	}
}

func postureScore(checks []types.PostureCheck) float64 {
	var total, score float64
	for _, c := range checks {
		switch c.Status {
		case "N/A":
			continue
		case "PASS":
			total++
			score++
		case "PARTIAL":
			total++
			score += 0.5
		case "FAIL":
			total++
		}
	}
	if total == 0 {
		return 100.0
	}
	return (score / total) * 100.0
}
