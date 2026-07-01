package authflow

import (
	gotypes "go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

type authPattern struct {
	substring string
	kind      string // authn, authz, validator, session
}

var patterns = []authPattern{
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
}

// Pass implements the auth flow analysis.
type Pass struct{}

func (p *Pass) Name() string { return "authflow" }

func (p *Pass) Run(ctx *passes.Context) error {
	prog := ctx.Program

	authFuncs := findAuthFunctions(prog)
	entries := findEntryPoints(prog)

	if len(entries) == 0 || len(authFuncs) == 0 {
		return nil
	}

	for _, entry := range entries {
		flow := traceAuthFlow(prog, entry, authFuncs)
		if flow != nil {
			ctx.Result.AuthFlows = append(ctx.Result.AuthFlows, *flow)
		}
	}

	sort.Slice(ctx.Result.AuthFlows, func(i, j int) bool {
		return ctx.Result.AuthFlows[i].Name < ctx.Result.AuthFlows[j].Name
	})

	return nil
}

type classifiedFunc struct {
	fn   *ssa.Function
	kind string
}

func findAuthFunctions(prog *loader.Program) []classifiedFunc {
	var result []classifiedFunc
	seen := make(map[*ssa.Function]bool)

	for fn := range prog.CallGraph.Nodes {
		if fn == nil || seen[fn] || !prog.IsModuleFunc(fn) {
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

func findEntryPoints(prog *loader.Program) []*ssa.Function {
	var entries []*ssa.Function
	seen := make(map[*ssa.Function]bool)

	for fn := range prog.CallGraph.Nodes {
		if fn == nil || seen[fn] || !prog.IsModuleFunc(fn) {
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
	if fn.Name() == "ServeHTTP" {
		// ServeHTTP must have a receiver (it's a method) and the correct param types.
		if fn.Signature.Recv() == nil {
			return false
		}
		if fn.Signature.Params().Len() == 2 && hasHTTPParams(fn.Signature) {
			return true
		}
		return false
	}
	name := fn.Name()
	if strings.HasPrefix(name, "Handle") || strings.HasPrefix(name, "handler") {
		sig := fn.Signature
		if sig.Params().Len() >= 2 && hasHTTPParams(sig) {
			return true
		}
	}
	return false
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

func traceAuthFlow(prog *loader.Program, entry *ssa.Function, authFuncs []classifiedFunc) *types.AuthFlow {
	reachable := forwardReachable(prog.CallGraph, entry)

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

	entryFile, entryLine := loader.FunctionLocation(prog.Fset, entry)
	flow := &types.AuthFlow{
		Name: deriveFlowName(entry),
		Entry: types.Location{
			File:     loader.RelativePath(entryFile, prog.ModulePath),
			Line:     entryLine,
			Function: entry.Name(),
			Package:  packagePath(entry),
		},
	}

	// Use the first authn step as the primary, but log all steps for completeness.
	// In the future, additional steps could be surfaced in the output.
	if len(authnSteps) > 0 {
		fn := authnSteps[0].fn
		file, line := loader.FunctionLocation(prog.Fset, fn)
		flow.Authentication = &types.AuthStep{
			Location: types.Location{
				File:     loader.RelativePath(file, prog.ModulePath),
				Line:     line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			},
		}
		// Record additional authn steps as validators so they aren't silently dropped.
		for _, extra := range authnSteps[1:] {
			ef, el := loader.FunctionLocation(prog.Fset, extra.fn)
			flow.Validators = append(flow.Validators, types.ValidatorInfo{
				Location: types.Location{
					File:     loader.RelativePath(ef, prog.ModulePath),
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
		file, line := loader.FunctionLocation(prog.Fset, fn)
		flow.Authorization = &types.AuthStep{
			Location: types.Location{
				File:     loader.RelativePath(file, prog.ModulePath),
				Line:     line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			},
		}
		for _, extra := range authzSteps[1:] {
			ef, el := loader.FunctionLocation(prog.Fset, extra.fn)
			flow.Validators = append(flow.Validators, types.ValidatorInfo{
				Location: types.Location{
					File:     loader.RelativePath(ef, prog.ModulePath),
					Line:     el,
					Function: extra.fn.Name(),
					Package:  packagePath(extra.fn),
				},
				Kind: "authz",
			})
		}
	}

	for _, vs := range validatorSteps {
		file, line := loader.FunctionLocation(prog.Fset, vs.fn)
		flow.Validators = append(flow.Validators, types.ValidatorInfo{
			Location: types.Location{
				File:     loader.RelativePath(file, prog.ModulePath),
				Line:     line,
				Function: vs.fn.Name(),
				Package:  packagePath(vs.fn),
			},
			Kind: inferValidatorKind(vs.fn.Name()),
		})
	}

	for _, ss := range sessionSteps {
		file, line := loader.FunctionLocation(prog.Fset, ss.fn)
		flow.Sessions = append(flow.Sessions, types.Location{
			File:     loader.RelativePath(file, prog.ModulePath),
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
