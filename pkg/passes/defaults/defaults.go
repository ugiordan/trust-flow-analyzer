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
			case *ast.GenDecl:
				p.analyzeKubebuilderDefaults(node, pkg, plat, result, fset, modulePath)
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

// analyzeKubebuilderDefaults scans struct type declarations for +kubebuilder:default=
// and +kubebuilder:validation:Optional annotations on fields. These define CRD field
// defaults that operators apply when users don't set a value.
func (p *Pass) analyzeKubebuilderDefaults(decl *ast.GenDecl, pkg *packages.Package, plat *platform.Knowledge, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	if decl.Tok != token.TYPE {
		return
	}

	for _, spec := range decl.Specs {
		typeSpec, ok := spec.(*ast.TypeSpec)
		if !ok {
			continue
		}

		structType, ok := typeSpec.Type.(*ast.StructType)
		if !ok {
			continue
		}

		typeName := pkg.PkgPath + "." + typeSpec.Name.Name

		for _, field := range structType.Fields.List {
			fieldName := ""
			if len(field.Names) > 0 {
				fieldName = field.Names[0].Name
			}
			if fieldName == "" {
				continue
			}

			// Kubebuilder markers can appear in struct tags or Go doc comments.
			// Collect all text to scan.
			searchText := ""
			if field.Tag != nil {
				searchText = field.Tag.Value
			}
			if field.Doc != nil {
				searchText += " " + field.Doc.Text()
			}
			if field.Comment != nil {
				searchText += " " + field.Comment.Text()
			}
			if searchText == "" {
				continue
			}

			qualifiedField := typeName + "." + fieldName

			if defaultVal, ok := extractKubebuilderDefault(searchText); ok {
				sem, known := plat.Lookup(fieldName)
				if !known {
					sem = platform.FieldSemantics{
						Field:          fieldName,
						EmptyMeaning:   "kubebuilder default: " + defaultVal,
						Permissiveness: classifyKubebuilderDefault(fieldName, defaultVal),
					}
				}

				pos := fset.Position(field.Pos())
				result.Defaults = append(result.Defaults, types.DefaultValue{
					Field: qualifiedField,
					Location: types.Location{
						File:    loader.RelativePath(pos.Filename, modulePath),
						Line:    pos.Line,
						Package: pkg.PkgPath,
					},
					LibraryDefault:  defaultVal,
					PlatformMeaning: sem.EmptyMeaning,
					Permissiveness:  sem.Permissiveness,
					OperatorDefault: defaultVal + " (kubebuilder)",
				})
			}

			if isOptionalSecurityField(fieldName, searchText) {
				pos := fset.Position(field.Pos())
				result.Defaults = append(result.Defaults, types.DefaultValue{
					Field: qualifiedField,
					Location: types.Location{
						File:    loader.RelativePath(pos.Filename, modulePath),
						Line:    pos.Line,
						Package: pkg.PkgPath,
					},
					LibraryDefault:  "nil (optional)",
					PlatformMeaning: "Security component absent when not configured",
					Permissiveness:  "PERMISSIVE",
					OperatorDefault: "nil (user must opt-in)",
				})
			}
		}
	}
}

// extractKubebuilderDefault parses +kubebuilder:default= from a struct tag.
// The annotation can appear in the json tag comment or as a Go comment above the field.
func extractKubebuilderDefault(tag string) (string, bool) {
	marker := "+kubebuilder:default="
	idx := strings.Index(tag, marker)
	if idx < 0 {
		return "", false
	}

	val := tag[idx+len(marker):]
	if end := strings.IndexAny(val, "` \n"); end >= 0 {
		val = val[:end]
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return "", false
	}
	return val, true
}

// classifyKubebuilderDefault determines if a kubebuilder default is security-relevant.
func classifyKubebuilderDefault(fieldName, value string) string {
	lower := strings.ToLower(fieldName)
	lowerVal := strings.ToLower(value)

	insecureDefaults := map[string]bool{
		"disable": true, "disabled": true, "false": true,
		"none": true, "off": true, "skip": true,
	}

	if strings.Contains(lower, "ssl") || strings.Contains(lower, "tls") {
		if insecureDefaults[lowerVal] {
			return "PERMISSIVE"
		}
	}

	if strings.Contains(lower, "auth") || strings.Contains(lower, "rbac") ||
		strings.Contains(lower, "proxy") || strings.Contains(lower, "security") {
		if insecureDefaults[lowerVal] || lowerVal == "" {
			return "PERMISSIVE"
		}
	}

	return "NEUTRAL"
}

// isOptionalSecurityField detects CRD fields for security components (auth proxies,
// TLS config, RBAC) that are pointer types with +optional. When nil, the security
// component is absent from the rendered deployment.
func isOptionalSecurityField(fieldName, tag string) bool {
	lower := strings.ToLower(fieldName)
	securityFields := []string{
		"rbacproxy", "kubeRBACProxy", "oauthproxy", "authproxy",
		"tls", "mtls", "auth", "authorization", "authorino",
	}

	isSecurityField := false
	for _, pattern := range securityFields {
		if strings.Contains(strings.ToLower(lower), strings.ToLower(pattern)) {
			isSecurityField = true
			break
		}
	}
	if !isSecurityField {
		return false
	}

	isOptional := strings.Contains(tag, "+optional") ||
		strings.Contains(tag, "omitempty")

	return isOptional
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
