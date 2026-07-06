package ir

import (
	"go/token"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// AnalysisProgram is the language-agnostic representation consumed by all passes.
// For Go repos, GoSSA is populated for precise SSA-based analysis.
// For non-Go repos, the tree-sitter fields (Functions, CallSites, Callees, Callers)
// provide heuristic analysis.
type AnalysisProgram struct {
	Language   string // "go", "python", "typescript", "rust"
	ModulePath string
	RootDir    string

	Functions     []FunctionInfo
	CallSites     []CallSiteInfo
	Callees       map[string][]string // function ID -> callee function IDs
	Callers       map[string][]string // function ID -> caller function IDs
	Files         map[string][]byte   // file path -> content
	ErrorPatterns []ErrorPatternInfo   // error patterns extracted by tree-sitter

	GoSSA *GoSSAData // nil for non-Go
}

// ErrorPatternInfo describes an error handling pattern extracted from source code
// by tree-sitter (raise statements, empty except blocks, etc.).
type ErrorPatternInfo struct {
	Kind     string // "raise", "empty_except"
	File     string
	Line     int
	FuncName string
	Package  string
	Message  string
}

// GoSSAData holds Go-specific SSA data. Only populated for Go repos.
type GoSSAData struct {
	Fset      *token.FileSet
	Packages  []*packages.Package
	SSA       *ssa.Program
	CallGraph *callgraph.Graph
}

// FunctionInfo describes a function extracted from source code.
type FunctionInfo struct {
	ID         string // unique: "pkg.TypeName.FuncName" or "file:line"
	Name       string
	File       string
	Line       int
	EndLine    int
	Package    string // package/module path
	TypeName   string // receiver/class name for methods (empty for standalone functions)
	Params     []ParamInfo
	ReturnType string // simplified return type description
	Decorators []string
	IsExported bool
	IsMethod   bool
}

// ParamInfo describes a function parameter.
type ParamInfo struct {
	Name string
	Type string
}

// CallSiteInfo describes a function call found in source code.
type CallSiteInfo struct {
	CalleeName   string
	File         string
	Line         int
	CallerFuncID string // ID of the enclosing function
	Arguments    []string
	IsMethodCall bool
	ReceiverExpr string // "self.client", "app", etc.
}

// Confidence levels for heuristic call graph edges.
const (
	ConfidenceCertain   = "certain"
	ConfidenceInferred  = "inferred"
	ConfidenceUncertain = "uncertain"
)

// ForwardReachable computes the set of function IDs reachable from root
// via the heuristic call graph. Used by non-Go passes as a replacement
// for SSA-based forwardReachable.
func (p *AnalysisProgram) ForwardReachable(rootID string) map[string]bool {
	visited := make(map[string]bool)
	queue := []string{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if visited[current] {
			continue
		}
		visited[current] = true
		for _, calleeID := range p.Callees[current] {
			if !visited[calleeID] {
				queue = append(queue, calleeID)
			}
		}
	}
	return visited
}

// FunctionByID returns the FunctionInfo with the given ID, or nil.
func (p *AnalysisProgram) FunctionByID(id string) *FunctionInfo {
	for i := range p.Functions {
		if p.Functions[i].ID == id {
			return &p.Functions[i]
		}
	}
	return nil
}

// FunctionsInFile returns all functions defined in the given file.
func (p *AnalysisProgram) FunctionsInFile(file string) []FunctionInfo {
	var result []FunctionInfo
	for _, f := range p.Functions {
		if f.File == file {
			result = append(result, f)
		}
	}
	return result
}
