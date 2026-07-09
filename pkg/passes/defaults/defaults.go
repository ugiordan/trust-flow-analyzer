package defaults

import (
	"bufio"
	"go/ast"
	"go/token"
	types2 "go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/platform"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass implements the default value analysis.
type Pass struct{}

func (p *Pass) Name() string { return "defaults" }

func (p *Pass) Run(ctx *passes.Context) error {
	var err error
	if ctx.Program.GoSSA != nil {
		err = p.runGo(ctx)
	} else {
		err = p.runGeneric(ctx)
	}
	if err != nil {
		return err
	}
	scanParamsEnvFiles(ctx)
	return nil
}

func (p *Pass) runGo(ctx *passes.Context) error {
	goSSA := ctx.Program.GoSSA
	modulePath := ctx.Program.ModulePath

	for _, pkg := range goSSA.Packages {
		p.analyzePackage(pkg, ctx.Platform, ctx.Result, goSSA.Fset, modulePath)
	}

	ctx.Result.Defaults = deduplicateDefaults(ctx.Result.Defaults)

	sort.Slice(ctx.Result.Defaults, func(i, j int) bool {
		return ctx.Result.Defaults[i].Field < ctx.Result.Defaults[j].Field
	})

	// Analyze webhook Default() methods for security field coverage.
	analyzeWebhookDefaults(goSSA, modulePath, ctx.Result)

	return nil
}

// configPatterns matches common configuration variable assignments in non-Go languages.
var configPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:DEBUG|TESTING)\s*[=:]\s*(?:True|true|1)`),
	regexp.MustCompile(`(?i)(?:SECRET_KEY|API_KEY|PASSWORD|TOKEN)\s*[=:]\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)(?:ALLOWED_HOSTS|CORS_ORIGIN)\s*[=:]\s*\[?\s*["']\*["']`),
	regexp.MustCompile(`(?i)(?:SSL|TLS|HTTPS)\s*[=:]\s*(?:False|false|0|disabled)`),
}

// runGeneric scans file content for configuration patterns in non-Go languages.
func (p *Pass) runGeneric(ctx *passes.Context) error {
	prog := ctx.Program

	for filePath, content := range prog.Files {
		relFile := relPath(prog.RootDir, filePath)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			for _, pat := range configPatterns {
				if pat.MatchString(line) {
					field := strings.TrimSpace(line)
					// Truncate long lines for display
					if len(field) > 80 {
						field = field[:80] + "..."
					}

					sem, known := ctx.Platform.Lookup(field)
					if !known {
						sem = platform.FieldSemantics{
							Field:          field,
							EmptyMeaning:   "potential security-relevant configuration",
							Permissiveness: "PERMISSIVE",
						}
					}

					ctx.Result.Defaults = append(ctx.Result.Defaults, types.DefaultValue{
						Field: field,
						Location: types.Location{
							File: relFile,
							Line: lineNum,
						},
						LibraryDefault:  field,
						PlatformMeaning: sem.EmptyMeaning,
						Permissiveness:  sem.Permissiveness,
					})
				}
			}
		}
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
	result := make([]types.DefaultValue, 0)
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

		// Skip Namespace fields on non-API structs. Setting Namespace on internal
		// controller structs (e.g. corev1.ObjectMeta in a reconciler) is a value
		// assignment, not a security-relevant default. Only keep Namespace matches
		// on CRD API types (paths containing "/api/" or "/apis/").
		if fieldName == "Namespace" && structTypeName != "" {
			if !strings.Contains(structTypeName, "/api/") && !strings.Contains(structTypeName, "/apis/") {
				// Also skip if the value is a non-zero assignment (e.g. "istio-system").
				// Non-zero values are explicit assignments, not defaults.
				if !isZeroValue(kv.Value) {
					continue
				}
			}
		}

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
	// Skip complex JSON objects/arrays. Space-splitting truncates them and they
	// are not simple security-relevant defaults.
	if strings.HasPrefix(val, "{") || strings.HasPrefix(val, "[") {
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

// securityEnvKeys are substrings in params.env key names that indicate
// security-relevant configuration.
var securityEnvKeys = []string{
	"NAMESPACE", "SECRET", "PASSWORD", "AUTH", "TLS", "SSL",
	"TOKEN", "CERT", "KEY", "RBAC", "PROXY", "ENCRYPT",
}

// scanParamsEnvFiles walks the project for params.env files (kustomize overlays)
// and flags empty values on security-critical keys as PERMISSIVE defaults.
func scanParamsEnvFiles(ctx *passes.Context) {
	rootDir := ctx.Program.RootDir
	if rootDir == "" {
		return
	}

	filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if info.Name() != "params.env" {
			return nil
		}

		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		rel := relPath(rootDir, path)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			upperKey := strings.ToUpper(key)

			isSecurityKey := false
			for _, substr := range securityEnvKeys {
				if strings.Contains(upperKey, substr) {
					isSecurityKey = true
					break
				}
			}
			if !isSecurityKey {
				continue
			}

			if value == "" {
				ctx.Result.Defaults = append(ctx.Result.Defaults, types.DefaultValue{
					Field: key,
					Location: types.Location{
						File: rel,
						Line: lineNum,
					},
					LibraryDefault:  "(empty)",
					OperatorDefault: "(empty) params.env (kustomize)",
					PlatformMeaning: "Empty value disables constraint. Security gate inactive when not set.",
					Permissiveness:  "PERMISSIVE",
				})
			}
		}

		return nil
	})
}

func inferOperatorDefault(value string, isDefault bool) string {
	if isDefault {
		return value + " (unchanged)"
	}
	return value
}

// relPath computes a relative path from rootDir. If rootDir is empty or
// the computation fails, the original path is returned.
func relPath(rootDir, filePath string) string {
	if rootDir == "" {
		return filePath
	}
	rel, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return filePath
	}
	return rel
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

// securityFieldNames lists the field names from platform knowledge that represent
// security components. When a webhook Default() method doesn't set these, it
// means the security component is absent by default.
var securityFieldNames = []string{
	"KubeRBACProxy",
	"OAuthProxy",
	"TLS",
	"Auth",
	"Authorino",
	"SslMode",
	"sslMode",
}

// analyzeWebhookDefaults finds webhook Default() methods via the SSA call graph
// and reports which security-relevant fields they set (or don't set).
func analyzeWebhookDefaults(goSSA *ir.GoSSAData, modulePath string, result *types.AnalysisResult) {
	seen := make(map[*ssa.Function]bool)

	for fn := range goSSA.CallGraph.Nodes {
		if fn == nil || seen[fn] {
			continue
		}
		seen[fn] = true

		// Only look at module functions.
		if fn.Package() == nil || !strings.HasPrefix(fn.Package().Pkg.Path(), modulePath) {
			continue
		}

		// Must be a method named "Default" with a receiver (webhook defaulter).
		if fn.Name() != "Default" || fn.Signature.Recv() == nil {
			continue
		}

		// Walk SSA blocks to find which fields are stored.
		fieldsSet := extractStoredFields(fn)

		// Determine which security fields are set and which are not.
		var setFields, unsetFields []string
		for _, sf := range securityFieldNames {
			if fieldsSet[sf] {
				setFields = append(setFields, sf)
			} else {
				unsetFields = append(unsetFields, sf)
			}
		}

		// Only report if the method is non-trivial (sets at least one field)
		// or if there are security fields it could set.
		if len(fieldsSet) == 0 && len(unsetFields) == 0 {
			continue
		}

		// Derive a human-friendly function name from the receiver type.
		funcName := deriveWebhookName(fn)
		file, line := loader.FunctionLocation(goSSA.Fset, fn)
		relFile := loader.RelativePath(file, modulePath)

		result.WebhookDefaults = append(result.WebhookDefaults, types.WebhookDefault{
			Function:    funcName,
			File:        relFile,
			Line:        line,
			FieldsSet:   setFields,
			FieldsUnset: unsetFields,
		})
	}

	sort.Slice(result.WebhookDefaults, func(i, j int) bool {
		return result.WebhookDefaults[i].Function < result.WebhookDefaults[j].Function
	})
}

// extractStoredFields walks a function's SSA blocks and returns a set of field
// names that are stored to via FieldAddr + Store instruction pairs.
func extractStoredFields(fn *ssa.Function) map[string]bool {
	fields := make(map[string]bool)

	if len(fn.Blocks) == 0 {
		return fields
	}

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			store, ok := instr.(*ssa.Store)
			if !ok {
				continue
			}

			// Check if the target of the store is a FieldAddr.
			fieldAddr, ok := store.Addr.(*ssa.FieldAddr)
			if !ok {
				continue
			}

			// Get the field name from the struct type.
			structType := fieldAddr.X.Type().Underlying()
			ptrType, isPtr := structType.(*types2.Pointer)
			if isPtr {
				structType = ptrType.Elem().Underlying()
			}
			st, isSt := structType.(*types2.Struct)
			if !isSt {
				continue
			}

			if fieldAddr.Field < st.NumFields() {
				fieldName := st.Field(fieldAddr.Field).Name()
				fields[fieldName] = true
			}
		}
	}

	return fields
}

// deriveWebhookName builds "ReceiverType.Default" from the SSA function.
func deriveWebhookName(fn *ssa.Function) string {
	recv := fn.Signature.Recv()
	if recv == nil {
		return fn.Name()
	}

	typeName := recv.Type().String()
	typeName = strings.TrimPrefix(typeName, "*")
	if idx := strings.LastIndex(typeName, "."); idx >= 0 {
		typeName = typeName[idx+1:]
	}
	return typeName + "." + fn.Name()
}
