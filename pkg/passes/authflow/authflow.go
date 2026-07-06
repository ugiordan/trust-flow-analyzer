package authflow

import (
	gotypes "go/types"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

type authPattern struct {
	substring string
	kind      string // authn, authz, validator, session
}

var patterns = []authPattern{
	// CamelCase (Go, TypeScript, Rust)
	{"Authenticate", "authn"},
	{"ValidateToken", "authn"},
	{"TokenReview", "authn"},
	{"VerifyToken", "authn"},
	{"CheckToken", "authn"},
	{"WithAuthentication", "authn"},

	{"Authorize", "authz"},
	{"CheckAccess", "authz"},
	{"SubjectAccessReview", "authz"},
	{"IsAllowed", "authz"},

	{"ValidateEmail", "validator"},
	{"isEmailValid", "validator"},
	{"ValidateDomain", "validator"},
	{"CheckGroups", "validator"},

	{"CreateSession", "session"},
	{"createSession", "session"},
	{"GetSession", "session"},
	{"getAuthenticatedSession", "session"},

	// snake_case (Python)
	{"authenticate", "authn"},
	{"validate_token", "authn"},
	{"verify_token", "authn"},
	{"check_token", "authn"},

	{"authorize", "authz"},
	{"check_access", "authz"},
	{"is_allowed", "authz"},
	{"check_permission", "authz"},

	{"validate_email", "validator"},
	{"check_groups", "validator"},
	{"validate_domain", "validator"},

	{"create_session", "session"},
	{"get_session", "session"},
}

// Pass implements the auth flow analysis.
type Pass struct{}

func (p *Pass) Name() string { return "authflow" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.Program.GoSSA != nil {
		return p.runGo(ctx)
	}
	return p.runGeneric(ctx)
}

func (p *Pass) runGo(ctx *passes.Context) error {
	goSSA := ctx.Program.GoSSA
	modulePath := ctx.Program.ModulePath

	authFuncs := findAuthFunctions(goSSA, modulePath)
	entries := findEntryPoints(goSSA, modulePath)

	if len(entries) == 0 || len(authFuncs) == 0 {
		return nil
	}

	for _, entry := range entries {
		flow := traceAuthFlow(goSSA, modulePath, entry, authFuncs)
		if flow != nil {
			ctx.Result.AuthFlows = append(ctx.Result.AuthFlows, *flow)
		}
	}

	sort.Slice(ctx.Result.AuthFlows, func(i, j int) bool {
		return ctx.Result.AuthFlows[i].Name < ctx.Result.AuthFlows[j].Name
	})

	return nil
}

// runGeneric uses the heuristic IR call graph for non-Go languages.
func (p *Pass) runGeneric(ctx *passes.Context) error {
	prog := ctx.Program

	// Find entry points by decorator patterns (e.g. @app.route, @router.get)
	var entryFuncs []ir.FunctionInfo
	for _, fn := range prog.Functions {
		if isGenericEntryPoint(fn) {
			entryFuncs = append(entryFuncs, fn)
		}
	}

	// Find auth functions by name patterns
	type genericClassified struct {
		fn   ir.FunctionInfo
		kind string
	}
	var authFuncs []genericClassified
	for _, fn := range prog.Functions {
		for _, pat := range patterns {
			if strings.Contains(fn.Name, pat.substring) {
				authFuncs = append(authFuncs, genericClassified{fn: fn, kind: pat.kind})
				break
			}
		}
	}

	if len(entryFuncs) == 0 || len(authFuncs) == 0 {
		return nil
	}

	for _, entry := range entryFuncs {
		reachable := prog.ForwardReachable(entry.ID)

		var authnSteps, authzSteps []genericClassified
		var validatorSteps, sessionSteps []genericClassified

		for _, af := range authFuncs {
			if !reachable[af.fn.ID] {
				continue
			}
			switch af.kind {
			case "authn":
				authnSteps = append(authnSteps, af)
			case "authz":
				authzSteps = append(authzSteps, af)
			case "validator":
				validatorSteps = append(validatorSteps, af)
			case "session":
				sessionSteps = append(sessionSteps, af)
			}
		}

		if len(authnSteps) == 0 && len(authzSteps) == 0 {
			continue
		}

		flow := &types.AuthFlow{
			Name: entry.Name,
			Entry: types.Location{
				File:     relPath(prog.RootDir, entry.File),
				Line:     entry.Line,
				Function: entry.Name,
				Package:  entry.Package,
			},
		}

		if len(authnSteps) > 0 {
			fn := authnSteps[0].fn
			flow.Authentication = &types.AuthStep{
				Location: types.Location{
					File:     relPath(prog.RootDir, fn.File),
					Line:     fn.Line,
					Function: fn.Name,
					Package:  fn.Package,
				},
			}
		}

		if len(authzSteps) > 0 {
			fn := authzSteps[0].fn
			flow.Authorization = &types.AuthStep{
				Location: types.Location{
					File:     relPath(prog.RootDir, fn.File),
					Line:     fn.Line,
					Function: fn.Name,
					Package:  fn.Package,
				},
			}
		}

		for _, vs := range validatorSteps {
			flow.Validators = append(flow.Validators, types.ValidatorInfo{
				Location: types.Location{
					File:     relPath(prog.RootDir, vs.fn.File),
					Line:     vs.fn.Line,
					Function: vs.fn.Name,
					Package:  vs.fn.Package,
				},
				Kind: inferValidatorKind(vs.fn.Name),
			})
		}

		for _, ss := range sessionSteps {
			flow.Sessions = append(flow.Sessions, types.Location{
				File:     relPath(prog.RootDir, ss.fn.File),
				Line:     ss.fn.Line,
				Function: ss.fn.Name,
				Package:  ss.fn.Package,
			})
		}

		flow.Posture = determinePosture(flow)
		ctx.Result.AuthFlows = append(ctx.Result.AuthFlows, *flow)
	}

	sort.Slice(ctx.Result.AuthFlows, func(i, j int) bool {
		return ctx.Result.AuthFlows[i].Name < ctx.Result.AuthFlows[j].Name
	})

	return nil
}

// isGenericEntryPoint checks whether a function looks like an HTTP entry point
// in a non-Go language (e.g. Python Flask/FastAPI routes).
func isGenericEntryPoint(fn ir.FunctionInfo) bool {
	routePatterns := []string{
		"@app.route", "@app.get", "@app.post", "@app.put", "@app.delete", "@app.patch",
		"@router.get", "@router.post", "@router.put", "@router.delete", "@router.patch",
		"@blueprint.route",
	}
	for _, dec := range fn.Decorators {
		for _, pat := range routePatterns {
			if strings.Contains(dec, pat) {
				return true
			}
		}
	}
	return false
}

type classifiedFunc struct {
	fn   *ssa.Function
	kind string
}

func findAuthFunctions(goSSA *ir.GoSSAData, modulePath string) []classifiedFunc {
	var result []classifiedFunc
	seen := make(map[*ssa.Function]bool)

	for fn := range goSSA.CallGraph.Nodes {
		if fn == nil || seen[fn] || !isModuleFunc(fn, modulePath) {
			continue
		}
		seen[fn] = true

		name := fn.Name()
		for _, p := range patterns {
			if strings.Contains(name, p.substring) {
				result = append(result, classifiedFunc{fn: fn, kind: p.kind})
				break
			}
		}
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].fn.String() < result[j].fn.String()
	})

	return result
}

// isModuleFunc returns true if the function belongs to the target module.
func isModuleFunc(fn *ssa.Function, modulePath string) bool {
	if fn == nil || fn.Package() == nil {
		return false
	}
	return strings.HasPrefix(fn.Package().Pkg.Path(), modulePath)
}

func findEntryPoints(goSSA *ir.GoSSAData, modulePath string) []*ssa.Function {
	var entries []*ssa.Function
	seen := make(map[*ssa.Function]bool)

	for fn := range goSSA.CallGraph.Nodes {
		if fn == nil || seen[fn] || !isModuleFunc(fn, modulePath) {
			continue
		}
		seen[fn] = true

		if isEntryPoint(fn) {
			entries = append(entries, fn)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].String() < entries[j].String()
	})

	return entries
}

func isEntryPoint(fn *ssa.Function) bool {
	// HTTP handlers: ServeHTTP method with (ResponseWriter, *Request) params
	if fn.Name() == "ServeHTTP" {
		if fn.Signature.Recv() == nil {
			return false
		}
		if fn.Signature.Params().Len() == 2 && hasHTTPParams(fn.Signature) {
			return true
		}
		return false
	}

	// HTTP handler functions: Handle*, handler* with HTTP params
	name := fn.Name()
	if strings.HasPrefix(name, "Handle") || strings.HasPrefix(name, "handler") {
		sig := fn.Signature
		if sig.Params().Len() >= 2 && hasHTTPParams(sig) {
			return true
		}
	}

	// Webhook handlers: Handle method with admission types, or Default/Validate methods
	if isWebhookEntryPoint(fn) {
		return true
	}

	// gRPC service methods: exported methods on a *Server receiver with
	// (context.Context, *Request) -> (*Response, error) signature pattern.
	if isGRPCEntryPoint(fn) {
		return true
	}

	// Controller Reconcile methods
	if fn.Name() == "Reconcile" && fn.Signature.Recv() != nil && fn.Signature.Params().Len() == 2 {
		for i := 0; i < fn.Signature.Params().Len(); i++ {
			paramType := fn.Signature.Params().At(i).Type().String()
			if strings.Contains(paramType, "reconcile.Request") || strings.Contains(paramType, "ctrl.Request") {
				return true
			}
		}
	}

	return false
}

func isWebhookEntryPoint(fn *ssa.Function) bool {
	if fn.Signature.Recv() == nil {
		return false
	}
	name := fn.Name()

	// admission.Handler.Handle method
	if name == "Handle" {
		for i := 0; i < fn.Signature.Params().Len(); i++ {
			paramType := fn.Signature.Params().At(i).Type().String()
			if strings.Contains(paramType, "admission.Request") || strings.Contains(paramType, "webhook.") {
				return true
			}
		}
	}

	// Defaulter/Validator webhook interfaces
	if name == "Default" || name == "ValidateCreate" || name == "ValidateUpdate" || name == "ValidateDelete" {
		recvType := fn.Signature.Recv().Type().String()
		pkgPath := ""
		if fn.Package() != nil {
			pkgPath = fn.Package().Pkg.Path()
		}
		combined := recvType + " " + pkgPath
		if strings.Contains(combined, "webhook") || strings.Contains(combined, "admission") ||
			strings.Contains(combined, "Defaulter") || strings.Contains(combined, "Validator") {
			return true
		}
	}

	return false
}

// isGRPCEntryPoint detects gRPC service method implementations. These are exported
// methods on a struct whose type name contains "Server" (e.g. ModelRegistryServiceServer),
// with a context.Context parameter and error return. This is a heuristic that catches
// the common protobuf-generated service implementation pattern.
func isGRPCEntryPoint(fn *ssa.Function) bool {
	if fn.Signature.Recv() == nil {
		return false
	}

	// Must be exported (starts with uppercase)
	name := fn.Name()
	if len(name) == 0 || name[0] < 'A' || name[0] > 'Z' {
		return false
	}

	// Receiver type must contain "Server"
	recvType := fn.Signature.Recv().Type().String()
	recvType = strings.TrimPrefix(recvType, "*")
	if !strings.Contains(recvType, "Server") {
		return false
	}

	// Must have at least 2 params, one of which is context.Context
	params := fn.Signature.Params()
	if params.Len() < 2 {
		return false
	}

	hasContext := false
	for i := 0; i < params.Len(); i++ {
		paramType := params.At(i).Type().String()
		if paramType == "context.Context" {
			hasContext = true
			break
		}
	}
	if !hasContext {
		return false
	}

	// Must return an error
	results := fn.Signature.Results()
	if results == nil || results.Len() == 0 {
		return false
	}

	hasError := false
	for i := 0; i < results.Len(); i++ {
		if results.At(i).Type().String() == "error" {
			hasError = true
			break
		}
	}

	return hasError
}

// hasHTTPParams returns true if the function signature contains http.ResponseWriter
// and *http.Request parameters.
func hasHTTPParams(sig *gotypes.Signature) bool {
	hasWriter := false
	hasRequest := false
	for i := 0; i < sig.Params().Len(); i++ {
		paramType := sig.Params().At(i).Type().String()
		if strings.Contains(paramType, "http.ResponseWriter") {
			hasWriter = true
		}
		if strings.Contains(paramType, "http.Request") {
			hasRequest = true
		}
	}
	return hasWriter && hasRequest
}

func traceAuthFlow(goSSA *ir.GoSSAData, modulePath string, entry *ssa.Function, authFuncs []classifiedFunc) *types.AuthFlow {
	reachable := forwardReachable(goSSA.CallGraph, entry)

	var authnSteps []classifiedFunc
	var authzSteps []classifiedFunc
	var validatorSteps []classifiedFunc
	var sessionSteps []classifiedFunc

	for _, af := range authFuncs {
		if !reachable[af.fn] {
			continue
		}
		switch af.kind {
		case "authn":
			authnSteps = append(authnSteps, af)
		case "authz":
			authzSteps = append(authzSteps, af)
		case "validator":
			validatorSteps = append(validatorSteps, af)
		case "session":
			sessionSteps = append(sessionSteps, af)
		}
	}

	if len(authnSteps) == 0 && len(authzSteps) == 0 {
		return nil
	}

	entryFile, entryLine := loader.FunctionLocation(goSSA.Fset, entry)
	flow := &types.AuthFlow{
		Name: deriveFlowName(entry),
		Entry: types.Location{
			File:     loader.RelativePath(entryFile, modulePath),
			Line:     entryLine,
			Function: entry.Name(),
			Package:  packagePath(entry),
		},
	}

	// Use the first authn step as the primary, but log all steps for completeness.
	// In the future, additional steps could be surfaced in the output.
	if len(authnSteps) > 0 {
		fn := authnSteps[0].fn
		file, line := loader.FunctionLocation(goSSA.Fset, fn)
		flow.Authentication = &types.AuthStep{
			Location: types.Location{
				File:     loader.RelativePath(file, modulePath),
				Line:     line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			},
		}
		// Record additional authn steps as validators so they aren't silently dropped.
		for _, extra := range authnSteps[1:] {
			ef, el := loader.FunctionLocation(goSSA.Fset, extra.fn)
			flow.Validators = append(flow.Validators, types.ValidatorInfo{
				Location: types.Location{
					File:     loader.RelativePath(ef, modulePath),
					Line:     el,
					Function: extra.fn.Name(),
					Package:  packagePath(extra.fn),
				},
				Kind: "authn",
			})
		}
	}

	// Use the first authz step as the primary, record extras as validators.
	if len(authzSteps) > 0 {
		fn := authzSteps[0].fn
		file, line := loader.FunctionLocation(goSSA.Fset, fn)
		flow.Authorization = &types.AuthStep{
			Location: types.Location{
				File:     loader.RelativePath(file, modulePath),
				Line:     line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			},
		}
		for _, extra := range authzSteps[1:] {
			ef, el := loader.FunctionLocation(goSSA.Fset, extra.fn)
			flow.Validators = append(flow.Validators, types.ValidatorInfo{
				Location: types.Location{
					File:     loader.RelativePath(ef, modulePath),
					Line:     el,
					Function: extra.fn.Name(),
					Package:  packagePath(extra.fn),
				},
				Kind: "authz",
			})
		}
	}

	for _, vs := range validatorSteps {
		file, line := loader.FunctionLocation(goSSA.Fset, vs.fn)
		flow.Validators = append(flow.Validators, types.ValidatorInfo{
			Location: types.Location{
				File:     loader.RelativePath(file, modulePath),
				Line:     line,
				Function: vs.fn.Name(),
				Package:  packagePath(vs.fn),
			},
			Kind: inferValidatorKind(vs.fn.Name()),
		})
	}

	for _, ss := range sessionSteps {
		file, line := loader.FunctionLocation(goSSA.Fset, ss.fn)
		flow.Sessions = append(flow.Sessions, types.Location{
			File:     loader.RelativePath(file, modulePath),
			Line:     line,
			Function: ss.fn.Name(),
			Package:  packagePath(ss.fn),
		})
	}

	flow.Posture = determinePosture(flow)

	return flow
}

func forwardReachable(cg *callgraph.Graph, root *ssa.Function) map[*ssa.Function]bool {
	const maxNodes = 10000

	visited := make(map[*ssa.Function]bool)
	node := cg.Nodes[root]
	if node == nil {
		return visited
	}

	queue := []*callgraph.Node{node}
	for len(queue) > 0 {
		if len(visited) >= maxNodes {
			break
		}

		current := queue[0]
		queue = queue[1:]

		if visited[current.Func] {
			continue
		}
		visited[current.Func] = true

		for _, edge := range current.Out {
			if edge.Callee != nil && !visited[edge.Callee.Func] {
				queue = append(queue, edge.Callee)
			}
		}
	}

	return visited
}

func deriveFlowName(fn *ssa.Function) string {
	if fn.Package() != nil {
		parts := strings.Split(fn.Package().Pkg.Path(), "/")
		last := parts[len(parts)-1]
		if fn.Name() != "ServeHTTP" {
			return last + "." + fn.Name()
		}
		recv := fn.Signature.Recv()
		if recv != nil {
			typeName := recv.Type().String()
			typeName = strings.TrimPrefix(typeName, "*")
			if idx := strings.LastIndex(typeName, "."); idx >= 0 {
				typeName = typeName[idx+1:]
			}
			return last + "." + typeName
		}
		return last
	}
	return fn.Name()
}

func packagePath(fn *ssa.Function) string {
	if fn.Package() != nil {
		return fn.Package().Pkg.Path()
	}
	return ""
}

func inferValidatorKind(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "email"):
		return "email"
	case strings.Contains(lower, "domain"):
		return "domain"
	case strings.Contains(lower, "group"):
		return "group"
	case strings.Contains(lower, "role"):
		return "role"
	default:
		return "unknown"
	}
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

func determinePosture(flow *types.AuthFlow) string {
	hasAuthn := flow.Authentication != nil
	hasAuthz := flow.Authorization != nil

	switch {
	case hasAuthn && hasAuthz:
		return "RESTRICTIVE"
	case hasAuthn && !hasAuthz:
		return "PERMISSIVE"
	default:
		// !hasAuthn && hasAuthz: authorization without authentication.
		// The !hasAuthn && !hasAuthz case cannot occur because traceAuthFlow
		// returns nil when neither authn nor authz steps are found.
		return "PARTIAL"
	}
}
