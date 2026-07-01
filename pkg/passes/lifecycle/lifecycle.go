package lifecycle

import (
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

var createPatterns = []string{
	"Create",
	"CreateOrUpdate",
	"CreateOrPatch",
}

var deletePatterns = []string{
	"Delete",
	"DeleteAllOf",
}

var ownerPatterns = []string{
	"SetOwnerReference",
	"SetControllerReference",
	"OwnerReference",
}

var finalizerPatterns = []string{
	"AddFinalizer",
	"RemoveFinalizer",
	"ContainsFinalizer",
}

// Pass implements the resource lifecycle analysis.
type Pass struct{}

func (p *Pass) Name() string { return "lifecycle" }

func (p *Pass) Run(ctx *passes.Context) error {
	prog := ctx.Program

	resources := make(map[string]*types.ResourceLifecycle)

	for _, fn := range loader.SortedModuleFunctions(prog) {
		if len(fn.Blocks) == 0 {
			continue
		}

		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}

				analyzeCall(prog, fn, call, resources)
			}
		}
	}

	for _, lc := range resources {
		lc.Orphanable = lc.Owner == nil && lc.Finalizer == nil
		ctx.Result.Lifecycles = append(ctx.Result.Lifecycles, *lc)
	}

	sort.Slice(ctx.Result.Lifecycles, func(i, j int) bool {
		return ctx.Result.Lifecycles[i].Resource < ctx.Result.Lifecycles[j].Resource
	})

	return nil
}

func analyzeCall(prog *loader.Program, fn *ssa.Function, call *ssa.Call, resources map[string]*types.ResourceLifecycle) {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return
	}

	calleeName := callee.Name()
	pos := prog.Fset.Position(call.Pos())
	loc := types.Location{
		File:     filepath.Base(pos.Filename),
		Line:     pos.Line,
		Function: fn.Name(),
		Package:  packagePath(fn),
	}

	resourceKey := inferResourceKey(fn, call)

	if matchesAny(calleeName, createPatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Create = loc
	}

	if matchesAny(calleeName, deletePatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Delete = &loc
	}

	if matchesAny(calleeName, ownerPatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Owner = &loc
	}

	if matchesAny(calleeName, finalizerPatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Finalizer = &loc
	}
}

func getOrCreate(resources map[string]*types.ResourceLifecycle, key string) *types.ResourceLifecycle {
	if lc, ok := resources[key]; ok {
		return lc
	}
	lc := &types.ResourceLifecycle{Resource: key}
	resources[key] = lc
	return lc
}

func inferResourceKey(fn *ssa.Function, call *ssa.Call) string {
	args := call.Call.Args
	for _, arg := range args {
		typeName := arg.Type().String()
		typeName = strings.TrimPrefix(typeName, "*")
		if idx := strings.LastIndex(typeName, "."); idx >= 0 {
			return typeName[idx+1:]
		}
		if typeName != "" {
			return typeName
		}
	}

	if fn.Package() != nil {
		return fn.Package().Pkg.Name() + "." + fn.Name()
	}
	return fn.Name()
}

func matchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if name == p || strings.HasSuffix(name, p) {
			return true
		}
	}
	return false
}

func packagePath(fn *ssa.Function) string {
	if fn.Package() != nil {
		return fn.Package().Pkg.Path()
	}
	return ""
}
