package contract

import (
	"go/token"
	"go/types"
	"sort"

	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	ttypes "github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Pass implements the contract analysis.
type Pass struct{}

func (p *Pass) Name() string { return "contract" }

func (p *Pass) Run(ctx *passes.Context) error {
	prog := ctx.Program

	for _, fn := range loader.SortedModuleFunctions(prog) {
		c := analyzeContract(prog, fn)
		if c != nil && len(c.Violations) > 0 {
			ctx.Result.Contracts = append(ctx.Result.Contracts, *c)
		}
	}

	sort.Slice(ctx.Result.Contracts, func(i, j int) bool {
		ci, cj := ctx.Result.Contracts[i], ctx.Result.Contracts[j]
		if ci.Function.Package != cj.Function.Package {
			return ci.Function.Package < cj.Function.Package
		}
		return ci.Function.Function < cj.Function.Function
	})

	return nil
}

func analyzeContract(prog *loader.Program, fn *ssa.Function) *ttypes.Contract {
	sig := fn.Signature
	results := sig.Results()
	if results == nil || results.Len() == 0 {
		return nil
	}

	var returns []ttypes.ReturnInfo
	hasErrorReturn := false

	for i := 0; i < results.Len(); i++ {
		r := results.At(i)
		isErr := isErrorType(r.Type())
		canBeNil := isNillable(r.Type())
		returns = append(returns, ttypes.ReturnInfo{
			Index:    i,
			Type:     r.Type().String(),
			IsError:  isErr,
			CanBeNil: canBeNil,
		})
		if isErr {
			hasErrorReturn = true
		}
	}

	if !hasErrorReturn {
		return nil
	}

	file, line := loader.FunctionLocation(prog.Fset, fn)
	contract := &ttypes.Contract{
		Function: ttypes.Location{
			File:     loader.RelativePath(file, prog.ModulePath),
			Line:     line,
			Function: fn.Name(),
			Package:  packagePath(fn),
		},
		Returns: returns,
	}

	node := prog.CallGraph.Nodes[fn]
	if node == nil {
		return contract
	}

	seen := make(map[*ssa.Function]bool)
	for _, edge := range node.In {
		callerFn := edge.Caller.Func
		if callerFn == nil || seen[callerFn] {
			continue
		}
		seen[callerFn] = true

		// Skip callers outside the analyzed module. External callers (stdlib,
		// dependencies) are not actionable findings for the project under analysis.
		if !prog.IsModuleFunc(callerFn) {
			continue
		}

		if edge.Site == nil {
			continue
		}

		violations := checkCallerHandling(prog, callerFn, edge.Site, fn, prog.ModulePath)
		contract.Violations = append(contract.Violations, violations...)
	}

	return contract
}

func checkCallerHandling(prog *loader.Program, caller *ssa.Function, site ssa.CallInstruction, callee *ssa.Function, modulePath string) []ttypes.ContractViolation {
	var violations []ttypes.ContractViolation

	sig := callee.Signature
	results := sig.Results()
	if results == nil || results.Len() == 0 {
		return nil
	}

	// Check if any return is an error type.
	hasError := false
	for i := 0; i < results.Len(); i++ {
		if isErrorType(results.At(i).Type()) {
			hasError = true
			break
		}
	}
	if !hasError {
		return nil
	}

	callValue, ok := site.(ssa.Value)
	if !ok {
		// The call is used as a statement (return values discarded entirely).
		// If the callee returns an error, this is an unchecked error.
		file, line := callerLocation(prog.Fset, caller, site)
		for i := 0; i < results.Len(); i++ {
			if isErrorType(results.At(i).Type()) {
				violations = append(violations, ttypes.ContractViolation{
					Caller: ttypes.Location{
						File:     loader.RelativePath(file, modulePath),
						Line:     line,
						Function: caller.Name(),
						Package:  packagePath(caller),
					},
					Description: caller.Name() + " discards all return values from " + callee.Name() + " (including error)",
					Kind:        "UNCHECKED_ERROR",
				})
			}
		}
		return violations
	}

	extract := findExtractUsage(callValue)

	for i := 0; i < results.Len(); i++ {
		r := results.At(i)
		if !isErrorType(r.Type()) {
			continue
		}

		if !isExtractUsed(extract, i, callValue, results.Len()) {
			file, line := callerLocation(prog.Fset, caller, site)
			violations = append(violations, ttypes.ContractViolation{
				Caller: ttypes.Location{
					File:     loader.RelativePath(file, modulePath),
					Line:     line,
					Function: caller.Name(),
					Package:  packagePath(caller),
				},
				Description: caller.Name() + " does not check error from " + callee.Name(),
				Kind:        "UNCHECKED_ERROR",
			})
		}
	}

	return violations
}

func findExtractUsage(v ssa.Value) map[int]bool {
	used := make(map[int]bool)
	refs := v.Referrers()
	if refs == nil {
		return used
	}
	for _, ref := range *refs {
		if ext, ok := ref.(*ssa.Extract); ok {
			extRefs := ext.Referrers()
			if extRefs != nil && len(*extRefs) > 0 {
				isBlank := true
				for _, r := range *extRefs {
					if _, ok := r.(*ssa.DebugRef); !ok {
						isBlank = false
						break
					}
				}
				if !isBlank {
					used[ext.Index] = true
				}
			}
		}
	}
	return used
}

func isExtractUsed(extract map[int]bool, index int, callValue ssa.Value, resultCount int) bool {
	// For single-return functions there is no Extract instruction.
	// Check referrers directly on the call value.
	if resultCount == 1 {
		refs := callValue.Referrers()
		if refs == nil {
			return false
		}
		for _, ref := range *refs {
			if _, ok := ref.(*ssa.DebugRef); ok {
				continue
			}
			return true
		}
		return false
	}
	if len(extract) == 0 {
		return false // no extracts found, error is unused
	}
	return extract[index]
}

func isErrorType(t types.Type) bool {
	return t.String() == "error" || types.Identical(t, types.Universe.Lookup("error").Type())
}

func isNillable(t types.Type) bool {
	switch t.Underlying().(type) {
	case *types.Pointer, *types.Interface, *types.Slice, *types.Map, *types.Chan, *types.Signature:
		return true
	default:
		return false
	}
}

func packagePath(fn *ssa.Function) string {
	if fn.Package() != nil {
		return fn.Package().Pkg.Path()
	}
	return ""
}

func callerLocation(fset *token.FileSet, caller *ssa.Function, site ssa.CallInstruction) (string, int) {
	pos := site.Pos()
	if pos.IsValid() {
		p := fset.Position(pos)
		return p.Filename, p.Line
	}
	return loader.FunctionLocation(fset, caller)
}

