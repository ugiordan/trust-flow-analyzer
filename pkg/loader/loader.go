package loader

import (
	"bufio"
	"fmt"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Program holds the loaded and analyzed Go program.
type Program struct {
	Fset       *token.FileSet
	Packages   []*packages.Package
	SSA        *ssa.Program
	CallGraph  *callgraph.Graph
	ModulePath string
}

// IsModuleFunc returns true if the function belongs to the target module (not stdlib or vendor).
func (p *Program) IsModuleFunc(fn *ssa.Function) bool {
	if fn == nil || fn.Package() == nil {
		return false
	}
	pkgPath := fn.Package().Pkg.Path()
	return strings.HasPrefix(pkgPath, p.ModulePath)
}

// Load loads Go packages from the given directory, builds SSA, and constructs a VTA call graph.
func Load(dir string, stderr io.Writer) (*Program, error) {
	if stderr == nil {
		stderr = os.Stderr
	}

	modulePath, err := readModulePath(dir)
	if err != nil {
		return nil, fmt.Errorf("reading module path: %w", err)
	}

	cfg := &packages.Config{
		Mode: packages.NeedName |
			packages.NeedFiles |
			packages.NeedSyntax |
			packages.NeedTypes |
			packages.NeedTypesInfo |
			packages.NeedDeps |
			packages.NeedImports,
		Dir: dir,
	}

	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, fmt.Errorf("loading packages: %w", err)
	}

	if len(pkgs) == 0 {
		return nil, fmt.Errorf("no packages found in %s", dir)
	}

	var hasErrors bool
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			fmt.Fprintf(stderr, "warning: %s: %v\n", pkg.PkgPath, e)
			hasErrors = true
		}
	}

	if allErrors(pkgs) {
		return nil, fmt.Errorf("all packages have errors, cannot proceed")
	}

	if hasErrors {
		fmt.Fprintf(stderr, "proceeding with partial analysis despite package errors\n")
	}

	prog, _ := ssautil.AllPackages(pkgs, ssa.InstantiateGenerics)
	prog.Build()

	cg := vta.CallGraph(ssautil.AllFunctions(prog), nil)

	return &Program{
		Fset:       prog.Fset,
		Packages:   pkgs,
		SSA:        prog,
		CallGraph:  cg,
		ModulePath: modulePath,
	}, nil
}

// FunctionLocation returns file:line for an SSA function using its position.
func FunctionLocation(fset *token.FileSet, fn *ssa.Function) (file string, line int) {
	pos := fn.Pos()
	if !pos.IsValid() {
		return "", 0
	}
	p := fset.Position(pos)
	return p.Filename, p.Line
}

// SortedModuleFunctions returns functions from the call graph that belong to the target module,
// sorted by package path and name for deterministic output.
func SortedModuleFunctions(prog *Program) []*ssa.Function {
	seen := make(map[*ssa.Function]bool)
	var fns []*ssa.Function
	for fn := range prog.CallGraph.Nodes {
		if fn != nil && !seen[fn] && prog.IsModuleFunc(fn) {
			seen[fn] = true
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool {
		pi, pj := fns[i].Package(), fns[j].Package()
		if pi != nil && pj != nil && pi.Pkg.Path() != pj.Pkg.Path() {
			return pi.Pkg.Path() < pj.Pkg.Path()
		}
		return fns[i].Name() < fns[j].Name()
	})
	return fns
}

func readModulePath(dir string) (string, error) {
	gomod := filepath.Join(dir, "go.mod")
	f, err := os.Open(gomod)
	if err != nil {
		return "", fmt.Errorf("opening go.mod: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module")), nil
		}
	}
	return "", fmt.Errorf("module directive not found in go.mod")
}

func allErrors(pkgs []*packages.Package) bool {
	for _, pkg := range pkgs {
		if len(pkg.Errors) == 0 {
			return false
		}
	}
	return true
}
