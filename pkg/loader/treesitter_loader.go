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
//
// NOTE: this is a package-level mutable map. AddSkipDirs mutates it globally,
// which is fine for the CLI (single invocation per process) but would be unsafe
// for concurrent library usage. If trust-flow-analyzer is ever embedded as a
// library, skipDirs should be moved into a per-invocation context or protected
// with a sync.RWMutex.
var skipDirs = map[string]bool{
	".git":         true,
	"__pycache__":  true,
	"node_modules": true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"vendor":       true,
	".tox":         true,
	"dist":         true,
	"build":        true,
	"public":       true,
	"static":       true,
	".next":        true,
	"coverage":     true,
	".nyc_output":  true,
	"out":          true,
}

// AddSkipDirs adds custom directory names to the skip list. This is called by
// the CLI when a user config provides custom skip_dirs.
func AddSkipDirs(dirs []string) {
	for _, d := range dirs {
		skipDirs[d] = true
	}
}

// ShouldSkipDir returns true if the given directory name is in the skip set.
// Passes that walk the filesystem should use this instead of maintaining their
// own copy of the skip list.
func ShouldSkipDir(name string) bool {
	return skipDirs[name]
}

// SkipDirsCopy returns a copy of the current skip dirs set. This is used to
// populate passes.Context.SkipDirs so passes can merge custom dirs without
// importing the loader package.
func SkipDirsCopy() map[string]bool {
	cp := make(map[string]bool, len(skipDirs))
	for k, v := range skipDirs {
		cp[k] = v
	}
	return cp
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
		fmt.Fprintf(stderr, "warning: no tree-sitter parser for %s, running config-only analysis\n", lang)
		return &ir.AnalysisProgram{
			Language:   lang,
			ModulePath: projectName,
			RootDir:    dir,
			Files:      make(map[string][]byte),
		}, nil
	}

	exts := make(map[string]bool)
	for _, ext := range parser.Extensions() {
		exts[ext] = true
	}

	var allFunctions []ir.FunctionInfo
	var allCallSites []ir.CallSiteInfo
	var allErrorPatterns []ir.ErrorPatternInfo
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
		name := info.Name()
		if strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.ts") ||
			strings.HasSuffix(name, ".bundle.js") || strings.Contains(name, ".chunk.") {
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

		for _, ep := range result.Errors {
			relPath, relErr := filepath.Rel(dir, ep.File)
			if relErr != nil {
				relPath = ep.File
			}
			fnPkg := ""
			for _, fn := range result.Functions {
				if fn.Name == ep.FuncName && fn.File == ep.File {
					fnPkg = fn.Package
					break
				}
			}
			allErrorPatterns = append(allErrorPatterns, ir.ErrorPatternInfo{
				Kind:     ep.Kind,
				File:     relPath,
				Line:     ep.Line,
				FuncName: ep.FuncName,
				Package:  fnPkg,
				Message:  ep.Message,
			})
		}

		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walking directory %s: %w", dir, walkErr)
	}

	callees, callers := treesitter.BuildCallGraph(allFunctions, allCallSites)

	return &ir.AnalysisProgram{
		Language:      lang,
		ModulePath:    projectName,
		RootDir:       dir,
		Functions:     allFunctions,
		CallSites:     allCallSites,
		Callees:       callees,
		Callers:       callers,
		Files:         files,
		ErrorPatterns: allErrorPatterns,
		GoSSA:         nil,
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
		prog, goErr := LoadGo(dir, stderr)
		if goErr != nil {
			fmt.Fprintf(stderr, "warning: Go SSA loading failed (%v), falling back to tree-sitter\n", goErr)
			return LoadTreeSitter(dir, lang, stderr)
		}
		return prog, nil
	default:
		return LoadTreeSitter(dir, lang, stderr)
	}
}

// newParser creates the appropriate tree-sitter parser for the given language.
func newParser(rootDir string, lang string) (treesitter.Parser, error) {
	switch strings.ToLower(lang) {
	case "python":
		return treesitter.NewPythonParser(rootDir), nil
	case "typescript":
		return treesitter.NewTypeScriptParser(rootDir), nil
	case "rust":
		return treesitter.NewRustParser(rootDir), nil
	default:
		return nil, fmt.Errorf("unsupported language for tree-sitter parsing: %s", lang)
	}
}
