package errorprop

import (
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	ttypes "github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

var errorCreators = []string{
	"errors.New",
	"fmt.Errorf",
	"errors.Wrap",
	"errors.Wrapf",
	"errors.WithStack",
	"errors.WithMessage",
}

// Pass implements the error propagation analysis.
type Pass struct{}

func (p *Pass) Name() string { return "errorprop" }

func (p *Pass) Run(ctx *passes.Context) error {
	prog := ctx.Program

	for _, fn := range loader.SortedModuleFunctions(prog) {
		paths := analyzeErrorPaths(prog, fn)
		ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, paths...)
	}

	sort.Slice(ctx.Result.ErrorPaths, func(i, j int) bool {
		oi, oj := ctx.Result.ErrorPaths[i].Origin, ctx.Result.ErrorPaths[j].Origin
		if oi.Package != oj.Package {
			return oi.Package < oj.Package
		}
		if oi.File != oj.File {
			return oi.File < oj.File
		}
		return oi.Line < oj.Line
	})

	return nil
}

func analyzeErrorPaths(prog *loader.Program, fn *ssa.Function) []ttypes.ErrorPath {
	if len(fn.Blocks) == 0 {
		return nil
	}

	var paths []ttypes.ErrorPath

	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}

			if !isErrorCreation(call) {
				continue
			}

			pos := prog.Fset.Position(call.Pos())
			origin := ttypes.Location{
				File:     filepath.Base(pos.Filename),
				Line:     pos.Line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			}

			handlers, dropped := traceErrorValue(prog, call, fn)

			path := ttypes.ErrorPath{
				Origin:   origin,
				Handlers: handlers,
				Dropped:  dropped,
				FailMode: inferFailMode(fn, block, dropped),
			}
			paths = append(paths, path)
		}
	}

	return paths
}

func isErrorCreation(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil {
		return false
	}

	fullName := callee.String()
	for _, creator := range errorCreators {
		if strings.HasSuffix(fullName, creator) || strings.Contains(fullName, creator) {
			return true
		}
	}

	return false
}

func traceErrorValue(prog *loader.Program, errorVal ssa.Value, fn *ssa.Function) ([]ttypes.ErrorHandler, bool) {
	var handlers []ttypes.ErrorHandler
	dropped := true

	refs := errorVal.Referrers()
	if refs == nil {
		return handlers, true
	}

	for _, ref := range *refs {
		pos := prog.Fset.Position(ref.Pos())
		loc := ttypes.Location{
			File:     filepath.Base(pos.Filename),
			Line:     pos.Line,
			Function: fn.Name(),
			Package:  packagePath(fn),
		}

		switch r := ref.(type) {
		case *ssa.Return:
			handlers = append(handlers, ttypes.ErrorHandler{Location: loc, Kind: "RETURN"})
			dropped = false

		case *ssa.Call:
			callee := r.Call.StaticCallee()
			if callee != nil && isLoggingFunction(callee.Name()) {
				handlers = append(handlers, ttypes.ErrorHandler{Location: loc, Kind: "LOG"})
				dropped = false
			} else if callee != nil && isWrappingFunction(callee.Name()) {
				handlers = append(handlers, ttypes.ErrorHandler{Location: loc, Kind: "WRAP"})
				dropped = false
			}

		case *ssa.Extract:
			subRefs := r.Referrers()
			if subRefs == nil || len(*subRefs) == 0 {
				handlers = append(handlers, ttypes.ErrorHandler{Location: loc, Kind: "DROP"})
			} else {
				for _, subRef := range *subRefs {
					if _, ok := subRef.(*ssa.DebugRef); ok {
						continue
					}
					dropped = false
					break
				}
			}

		case *ssa.Store:
			dropped = false

		case *ssa.Phi:
			dropped = false

		case *ssa.DebugRef:
			// ignore debug refs
		}
	}

	return handlers, dropped
}

func isLoggingFunction(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"log", "error", "warn", "info", "debug", "fatal", "print"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isWrappingFunction(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "wrap") || strings.Contains(lower, "errorf")
}

func inferFailMode(_ *ssa.Function, block *ssa.BasicBlock, dropped bool) string {
	if dropped {
		return "OPEN"
	}

	for _, instr := range block.Instrs {
		if ret, ok := instr.(*ssa.Return); ok {
			for _, result := range ret.Results {
				if isNilValue(result) {
					return "OPEN"
				}
			}
		}
	}

	return "CLOSED"
}

func isNilValue(v ssa.Value) bool {
	if c, ok := v.(*ssa.Const); ok {
		return c.IsNil()
	}
	return false
}

func packagePath(fn *ssa.Function) string {
	if fn.Package() != nil {
		return fn.Package().Pkg.Path()
	}
	return ""
}

