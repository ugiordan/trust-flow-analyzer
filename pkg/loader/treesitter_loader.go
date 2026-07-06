package loader

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/langdetect"
	"github.com/ugiordan/trust-flow-analyzer/pkg/treesitter"
)

// skipDirs is the set of directory names to skip during tree-sitter file walks.
var skipDirs = map[string]bool{
	".git":        true,
	"__pycache__": true,
	"node_modules": true,
	"venv":        true,
	".venv":       true,
	"target":      true,
	"vendor":      true,
	".tox":        true,
}

// LoadTreeSitter loads a non-Go project via tree-sitter parsing and returns an
// ir.AnalysisProgram with heuristic call graph data. GoSSA is nil.
func LoadTreeSitter(dir string, lang string, stderr io.Writer) (*ir.AnalysisProgram, error) {
	if stderr == nil {
		stderr = os.Stderr
	}

	projectName := langdetect.DetectProjectName(dir, lang)

	parser, err := newParser(dir, lang)
	if err != nil {
		return nil, err
	}

	exts := make(map[string]bool)
	for _, ext := range parser.Extensions() {
		exts[ext] = true
	}

	var allFunctions []ir.FunctionInfo
	var allCallSites []ir.CallSiteInfo
	files := make(map[string][]byte)

	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(path)
		if !exts[ext] {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			fmt.Fprintf(stderr, "warning: cannot read %s: %v\n", path, readErr)
			return nil
		}
		files[path] = content

		result, parseErr := parser.ParseFile(path, content)
		if parseErr != nil {
			fmt.Fprintf(stderr, "warning: parse error in %s: %v\n", path, parseErr)
			return nil
		}

		allFunctions = append(allFunctions, result.Functions...)
		allCallSites = append(allCallSites, result.CallSites...)

		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, walkErr)
	}

	callees, callers := treesitter.BuildCallGraph(allFunctions, allCallSites)

	return &ir.AnalysisProgram{
		Language:   lang,
		ModulePath: projectName,
		RootDir:    dir,
		Functions:  allFunctions,
		CallSites:  allCallSites,
		Callees:    callees,
		Callers:    callers,
		Files:      files,
		GoSSA:      nil,
	}, nil
}

// LoadGo wraps the existing Load() function and produces an ir.AnalysisProgram.
// Go passes use GoSSA directly, so the heuristic fields (Functions, CallSites,
// Callees, Callers) are left empty.
func LoadGo(dir string, stderr io.Writer) (*ir.AnalysisProgram, error) {
	prog, err := Load(dir, stderr)
	if err != nil {
		return nil, err
	}

	return &ir.AnalysisProgram{
		Language:   "go",
		ModulePath: prog.ModulePath,
		RootDir:    dir,
		Functions:  nil,
		CallSites:  nil,
		Callees:    nil,
		Callers:    nil,
		Files:      nil,
		GoSSA: &ir.GoSSAData{
			Fset:      prog.Fset,
			Packages:  prog.Packages,
			SSA:       prog.SSA,
			CallGraph: prog.CallGraph,
		},
	}, nil
}

// LoadProject auto-detects the project language and dispatches to the appropriate
// loader. For Go projects it uses LoadGo (SSA-based). For other languages it uses
// LoadTreeSitter (heuristic tree-sitter based).
func LoadProject(dir string, stderr io.Writer) (*ir.AnalysisProgram, error) {
	lang, err := langdetect.DetectLanguage(dir)
	if err != nil {
		return nil, fmt.Errorf("detecting language: %w", err)
	}

	switch lang {
	case "go":
		return LoadGo(dir, stderr)
	default:
		return LoadTreeSitter(dir, lang, stderr)
	}
}

// newParser creates the appropriate tree-sitter parser for the given language.
func newParser(rootDir string, lang string) (treesitter.Parser, error) {
	switch strings.ToLower(lang) {
	case "python":
		return treesitter.NewPythonParser(rootDir), nil
	default:
		return nil, fmt.Errorf("unsupported language for tree-sitter parsing: %s", lang)
	}
}
