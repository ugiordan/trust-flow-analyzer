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
		// A resource is orphanable if it has no owner reference, no finalizer,
		// AND no explicit delete call (which would serve as manual cleanup).
		lc.Orphanable = lc.Owner == nil && lc.Finalizer == nil && lc.Delete == nil
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

	// For create/delete patterns, also verify the receiver type looks like a
	// K8s client to reduce false positives from unrelated Create/Delete methods.
	if matchesAny(calleeName, createPatterns) && isK8sClientCall(callee) {
		lc := getOrCreate(resources, resourceKey)
		lc.Create = loc
	} else if matchesAny(calleeName, deletePatterns) && isK8sClientCall(callee) {
		lc := getOrCreate(resources, resourceKey)
		lc.Delete = &loc
	} else if matchesAny(calleeName, ownerPatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Owner = &loc
	} else if matchesAny(calleeName, finalizerPatterns) {
		lc := getOrCreate(resources, resourceKey)
		lc.Finalizer = &loc
	}
}

// isK8sClientCall checks whether the callee's receiver or package path looks
// like a Kubernetes client. This reduces false positives from matching generic
// Create/Delete methods on non-K8s types.
func isK8sClientCall(callee *ssa.Function) bool {
	// Check the package path for known K8s client packages.
	if callee.Package() != nil {
		pkgPath := callee.Package().Pkg.Path()
		for _, pattern := range []string{"client", "sigs.k8s.io", "k8s.io/client-go", "controller-runtime"} {
			if strings.Contains(pkgPath, pattern) {
				return true
			}
		}
	}
	// Check the receiver type name.
	sig := callee.Signature
	if sig.Recv() != nil {
		recvType := sig.Recv().Type().String()
		for _, pattern := range []string{"Client", "client", "Interface"} {
			if strings.Contains(recvType, pattern) {
				return true
			}
		}
	}
	// If we can't determine, still match (conservative: avoid missing real K8s calls).
	return true
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

		// Skip context.Context: it's almost always the first arg and not the resource type.
		if typeName == "context.Context" {
			continue
		}

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
