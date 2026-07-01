package defaults

import (
	"go/ast"
	"go/token"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass implements the default value analysis.
type Pass struct{}

func (p *Pass) Name() string { return "defaults" }

func (p *Pass) Run(ctx *passes.Context) error {
	for _, pkg := range ctx.Program.Packages {
		p.analyzePackage(pkg, ctx.Platform, ctx.Result, ctx.Program.Fset)
	}

	sort.Slice(ctx.Result.Defaults, func(i, j int) bool {
		return ctx.Result.Defaults[i].Field < ctx.Result.Defaults[j].Field
	})

	return nil
}

func (p *Pass) analyzePackage(pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet) {
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				p.analyzeCompositeLit(node, pkg, plat, result, fset)
			case *ast.CallExpr:
				p.analyzeFlagCall(node, pkg, plat, result, fset)
			}
			return true
		})
	}
}

func (p *Pass) analyzeCompositeLit(lit *ast.CompositeLit, pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}

		fieldName := ident.Name
		sem, known := plat.Lookup(fieldName)
		if !known {
			continue
		}

		pos := fset.Position(kv.Pos())
		value := exprToString(kv.Value)
		isDefault := isZeroValue(kv.Value)

		result.Defaults = append(result.Defaults, types.DefaultValue{
			Field: fieldName,
			Location: types.Location{
				File:    filepath.Base(pos.Filename),
				Line:    pos.Line,
				Package: pkg.PkgPath,
			},
			LibraryDefault:  value,
			PlatformMeaning: sem.EmptyMeaning,
			Permissiveness:  sem.Permissiveness,
			OperatorDefault: inferOperatorDefault(value, isDefault),
		})
	}
}

func (p *Pass) analyzeFlagCall(call *ast.CallExpr, pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	methodName := sel.Sel.Name
	if !isFlagMethod(methodName) {
		return
	}

	if len(call.Args) < 2 {
		return
	}

	nameArg, ok := call.Args[0].(*ast.BasicLit)
	if !ok || nameArg.Kind != token.STRING {
		return
	}

	flagName := strings.Trim(nameArg.Value, `"`)
	sem, known := plat.Lookup(flagName)
	if !known {
		return
	}

	defaultValue := ""
	if len(call.Args) >= 3 {
		defaultValue = exprToString(call.Args[1])
	}

	pos := fset.Position(call.Pos())
	result.Defaults = append(result.Defaults, types.DefaultValue{
		Field: flagName,
		Location: types.Location{
			File:    filepath.Base(pos.Filename),
			Line:    pos.Line,
			Package: pkg.PkgPath,
		},
		LibraryDefault:  defaultValue,
		PlatformMeaning: sem.EmptyMeaning,
		Permissiveness:  sem.Permissiveness,
	})
}

func isFlagMethod(name string) bool {
	switch name {
	case "String", "StringVar", "Bool", "BoolVar", "Int", "IntVar",
		"StringSlice", "StringSliceVar", "StringArray", "StringArrayVar":
		return true
	default:
		return false
	}
}

func exprToString(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return strings.Trim(e.Value, `"`)
	case *ast.Ident:
		if e.Name == "nil" {
			return "nil"
		}
		if e.Name == "true" || e.Name == "false" {
			return e.Name
		}
		return e.Name
	case *ast.CompositeLit:
		if len(e.Elts) == 0 {
			return "[] (empty)"
		}
		return "[...]"
	case *ast.UnaryExpr:
		return exprToString(e.X)
	default:
		return "<complex>"
	}
}

func isZeroValue(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name == "nil" || e.Name == "false"
	case *ast.BasicLit:
		return e.Value == `""` || e.Value == "0"
	case *ast.CompositeLit:
		return len(e.Elts) == 0
	default:
		return false
	}
}

func inferOperatorDefault(value string, isDefault bool) string {
	if isDefault {
		return value + " (unchanged)"
	}
	return value
}
