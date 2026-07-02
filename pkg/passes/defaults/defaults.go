package defaults

import (
	"go/ast"
	"go/token"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass implements the default value analysis.
type Pass struct{}

func (p *Pass) Name() string { return "defaults" }

func (p *Pass) Run(ctx *passes.Context) error {
	for _, pkg := range ctx.Program.Packages {
		p.analyzePackage(pkg, ctx.Platform, ctx.Result, ctx.Program.Fset, ctx.Program.ModulePath)
	}

	ctx.Result.Defaults = deduplicateDefaults(ctx.Result.Defaults)

	sort.Slice(ctx.Result.Defaults, func(i, j int) bool {
		return ctx.Result.Defaults[i].Field < ctx.Result.Defaults[j].Field
	})

	return nil
}

func deduplicateDefaults(defaults []types.DefaultValue) []types.DefaultValue {
	type key struct {
		field string
		file  string
		line  int
	}
	seen := make(map[key]bool)
	var result []types.DefaultValue
	for _, d := range defaults {
		k := key{field: d.Field, file: d.Location.File, line: d.Location.Line}
		if seen[k] {
			continue
		}
		seen[k] = true
		result = append(result, d)
	}
	return result
}

func (p *Pass) analyzePackage(pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				p.analyzeCompositeLit(node, pkg, plat, result, fset, modulePath)
			case *ast.CallExpr:
				p.analyzeFlagCall(node, pkg, plat, result, fset, modulePath)
			}
			return true
		})
	}
}

func (p *Pass) analyzeCompositeLit(lit *ast.CompositeLit, pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	// Use TypesInfo to resolve the struct type for context-aware field matching.
	// This avoids false positives from fields with the same name in unrelated structs.
	structTypeName := ""
	if pkg.TypesInfo != nil && lit.Type != nil {
		if t := pkg.TypesInfo.TypeOf(lit.Type); t != nil {
			structTypeName = t.String()
		}
	}

	// Skip struct literals from K8s API types. Setting ObjectMeta.Namespace in a
	// struct literal is just assigning a namespace value, not configuring a
	// security-critical default. Only analyze structs from the target module or
	// its direct API types.
	if structTypeName != "" && isK8sAPIType(structTypeName) {
		return
	}

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

		// Try type-qualified lookup first (e.g. "TokenReviewSpec.audiences"),
		// then fall back to raw field name for backward compatibility.
		qualifiedName := fieldName
		if structTypeName != "" {
			qualifiedName = structTypeName + "." + fieldName
		}
		sem, known := plat.Lookup(qualifiedName)
		if !known {
			sem, known = plat.Lookup(fieldName)
		}
		if !known {
			continue
		}

		pos := fset.Position(kv.Pos())
		value := exprToString(kv.Value)
		isDefault := isZeroValue(kv.Value)

		result.Defaults = append(result.Defaults, types.DefaultValue{
			Field: qualifiedName,
			Location: types.Location{
				File:    loader.RelativePath(pos.Filename, modulePath),
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

func (p *Pass) analyzeFlagCall(call *ast.CallExpr, pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return
	}

	methodName := sel.Sel.Name
	if !isFlagMethod(methodName) {
		return
	}

	// For *Var methods (e.g. StringVar, BoolVar), the first arg is a pointer,
	// flag name is Args[1], default is Args[2]. For non-Var methods (e.g. String,
	// Bool), flag name is Args[0], default is Args[1].
	isVarMethod := strings.HasSuffix(methodName, "Var")

	nameIdx := 0
	defaultIdx := 1
	if isVarMethod {
		nameIdx = 1
		defaultIdx = 2
	}

	if len(call.Args) <= nameIdx {
		return
	}

	nameArg, ok := call.Args[nameIdx].(*ast.BasicLit)
	if !ok || nameArg.Kind != token.STRING {
		return
	}

	flagName := strings.Trim(nameArg.Value, `"`)
	sem, known := plat.Lookup(flagName)
	if !known {
		return
	}

	defaultValue := ""
	if len(call.Args) > defaultIdx {
		defaultValue = exprToString(call.Args[defaultIdx])
	}

	pos := fset.Position(call.Pos())
	result.Defaults = append(result.Defaults, types.DefaultValue{
		Field: flagName,
		Location: types.Location{
			File:    loader.RelativePath(pos.Filename, modulePath),
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
		return e.Op.String() + exprToString(e.X)
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

// isK8sAPIType returns true for K8s standard API types where field assignments
// like Namespace are just value-setting, not security-relevant defaults.
func isK8sAPIType(typeName string) bool {
	prefixes := []string{
		"k8s.io/api/",
		"k8s.io/apimachinery/",
		"k8s.io/client-go/",
		"crypto/tls",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(typeName, p) {
			return true
		}
	}
	return false
}
