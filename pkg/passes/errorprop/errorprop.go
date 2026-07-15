package errorprop

import (
	"bufio"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	ttypes "github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// errorCreator pairs a package path suffix with the exact function name for precise matching.
type errorCreator struct {
	pkgSuffix string
	funcName  string
}

var errorCreators = []errorCreator{
	{"errors", "New"},
	{"fmt", "Errorf"},
	{"errors", "Wrap"},
	{"errors", "Wrapf"},
	{"errors", "WithStack"},
	{"errors", "WithMessage"},
}

// Pass implements the error propagation analysis.
type Pass struct{}

func (p *Pass) Name() string { return "errorprop" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.Program.GoSSA != nil {
		return p.runGo(ctx)
	}
	return p.runGeneric(ctx)
}

func (p *Pass) runGo(ctx *passes.Context) error {
	goSSA := ctx.Program.GoSSA
	modulePath := ctx.Program.ModulePath

	for _, fn := range sortedModuleFunctions(goSSA, modulePath) {
		paths := analyzeErrorPaths(goSSA, modulePath, fn)
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

// Python error patterns for regex-based scanning.
var (
	raisePattern      = regexp.MustCompile(`^\s*raise\s+`)
	emptyExceptPattern = regexp.MustCompile(`^\s*except\s*(?:\w+\s*)?:\s*$`)
	passPattern        = regexp.MustCompile(`^\s*pass\s*(#.*)?$`)
)

// runGeneric converts error patterns to ErrorPaths. When tree-sitter error
// patterns are available (populated by the loader from tree-sitter AST), they
// are used directly because tree-sitter handles all forms accurately (including
// "except Exception as e: pass" and "pass" followed by real code). The regex
// scanner is the fallback for cases where ErrorPatterns is empty.
func (p *Pass) runGeneric(ctx *passes.Context) error {
	prog := ctx.Program

	if len(prog.ErrorPatterns) > 0 {
		return p.runFromTreeSitterPatterns(ctx)
	}
	return p.runRegexFallback(ctx)
}

// runFromTreeSitterPatterns converts tree-sitter extracted ErrorPatternInfo
// entries into ErrorPath results.
func (p *Pass) runFromTreeSitterPatterns(ctx *passes.Context) error {
	for _, ep := range ctx.Program.ErrorPatterns {
		switch ep.Kind {
		case "raise", "throw":
			ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
				Origin: ttypes.Location{
					File:     ep.File,
					Line:     ep.Line,
					Function: ep.FuncName,
					Package:  ep.Package,
				},
				Handlers: []ttypes.ErrorHandler{{
					Location: ttypes.Location{File: ep.File, Line: ep.Line, Function: ep.FuncName, Package: ep.Package},
					Kind:     "RAISE",
				}},
				Dropped:  false,
				FailMode: "CLOSED",
			})
		case "empty_except", "empty_catch":
			ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
				Origin: ttypes.Location{
					File:     ep.File,
					Line:     ep.Line,
					Function: ep.FuncName,
					Package:  ep.Package,
				},
				Handlers: nil,
				Dropped:  true,
				FailMode: "OPEN",
			})
		case "unwrap":
			// Rust .unwrap()/.expect() will panic on None/Err: fail-open behavior
			ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
				Origin: ttypes.Location{
					File:     ep.File,
					Line:     ep.Line,
					Function: ep.FuncName,
					Package:  ep.Package,
				},
				Handlers: []ttypes.ErrorHandler{{
					Location: ttypes.Location{File: ep.File, Line: ep.Line, Function: ep.FuncName, Package: ep.Package},
					Kind:     "PANIC",
				}},
				Dropped:  false,
				FailMode: "CLOSED",
			})
		case "panic":
			// Explicit panic/todo!/unimplemented! macro invocation
			ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
				Origin: ttypes.Location{
					File:     ep.File,
					Line:     ep.Line,
					Function: ep.FuncName,
					Package:  ep.Package,
				},
				Handlers: []ttypes.ErrorHandler{{
					Location: ttypes.Location{File: ep.File, Line: ep.Line, Function: ep.FuncName, Package: ep.Package},
					Kind:     "PANIC",
				}},
				Dropped:  false,
				FailMode: "CLOSED",
			})
		}
	}

	sort.Slice(ctx.Result.ErrorPaths, func(i, j int) bool {
		oi, oj := ctx.Result.ErrorPaths[i].Origin, ctx.Result.ErrorPaths[j].Origin
		if oi.File != oj.File {
			return oi.File < oj.File
		}
		return oi.Line < oj.Line
	})

	return nil
}

// runRegexFallback scans source files for error handling patterns using regex.
// Used only when tree-sitter error patterns are not available.
func (p *Pass) runRegexFallback(ctx *passes.Context) error {
	prog := ctx.Program

	for filePath, content := range prog.Files {
		relPath := relativePath(prog.RootDir, filePath)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineNum := 0
		inEmptyExcept := false
		exceptLine := 0
		exceptIndent := 0

		for scanner.Scan() {
			lineNum++
			line := scanner.Text()

			// Detect raise statements
			if raisePattern.MatchString(line) {
				ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
					Origin: ttypes.Location{
						File: relPath,
						Line: lineNum,
					},
					Handlers: []ttypes.ErrorHandler{{
						Location: ttypes.Location{File: relPath, Line: lineNum},
						Kind:     "RAISE",
					}},
					Dropped:  false,
					FailMode: "CLOSED",
				})
			}

			if inEmptyExcept {
				trimmed := strings.TrimSpace(line)
				// Skip blank lines and comment-only lines inside the except body
				if trimmed == "" || strings.HasPrefix(trimmed, "#") {
					continue
				}
				// Check if indentation decreased (left the except block)
				currentIndent := indentLevel(line)
				if currentIndent <= exceptIndent {
					// Exited the except block without finding a real statement.
					// This means the except body was empty.
					ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
						Origin: ttypes.Location{
							File: relPath,
							Line: exceptLine,
						},
						Handlers: nil,
						Dropped:  true,
						FailMode: "OPEN",
					})
					inEmptyExcept = false
					// Re-check this line for new except/raise patterns.
					// Check raise BEFORE except so that a raise immediately
					// after an empty except block is not swallowed.
					if raisePattern.MatchString(line) {
						ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
							Origin: ttypes.Location{
								File: relPath,
								Line: lineNum,
							},
							Handlers: []ttypes.ErrorHandler{{
								Location: ttypes.Location{File: relPath, Line: lineNum},
								Kind:     "RAISE",
							}},
							Dropped:  false,
							FailMode: "CLOSED",
						})
					}
					if emptyExceptPattern.MatchString(line) {
						inEmptyExcept = true
						exceptLine = lineNum
						exceptIndent = indentLevel(line)
					}
					continue
				}
				// Still inside except body, check if it's pass or ellipsis
				if passPattern.MatchString(line) || trimmed == "..." {
					ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
						Origin: ttypes.Location{
							File: relPath,
							Line: exceptLine,
						},
						Handlers: nil,
						Dropped:  true,
						FailMode: "OPEN",
					})
				}
				inEmptyExcept = false
			}

			// Detect empty except blocks (except: followed by pass or nothing).
			// This check must come AFTER the inEmptyExcept handling so that a
			// consecutive except: line finalizes the previous empty except first.
			if emptyExceptPattern.MatchString(line) {
				inEmptyExcept = true
				exceptLine = lineNum
				exceptIndent = indentLevel(line)
				continue
			}
		}

		// Handle case where file ends while inside an empty except block
		if inEmptyExcept {
			ctx.Result.ErrorPaths = append(ctx.Result.ErrorPaths, ttypes.ErrorPath{
				Origin: ttypes.Location{
					File: relPath,
					Line: exceptLine,
				},
				Handlers: nil,
				Dropped:  true,
				FailMode: "OPEN",
			})
		}
	}

	sort.Slice(ctx.Result.ErrorPaths, func(i, j int) bool {
		oi, oj := ctx.Result.ErrorPaths[i].Origin, ctx.Result.ErrorPaths[j].Origin
		if oi.File != oj.File {
			return oi.File < oj.File
		}
		return oi.Line < oj.Line
	})

	return nil
}

func sortedModuleFunctions(goSSA *ir.GoSSAData, modulePath string) []*ssa.Function {
	seen := make(map[*ssa.Function]bool)
	var fns []*ssa.Function
	for fn := range goSSA.CallGraph.Nodes {
		if fn != nil && !seen[fn] && isModuleFunc(fn, modulePath) {
			seen[fn] = true
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool {
		return fns[i].String() < fns[j].String()
	})
	return fns
}

func isModuleFunc(fn *ssa.Function, modulePath string) bool {
	if fn == nil || fn.Package() == nil {
		return false
	}
	return strings.HasPrefix(fn.Package().Pkg.Path(), modulePath)
}

func analyzeErrorPaths(goSSA *ir.GoSSAData, modulePath string, fn *ssa.Function) []ttypes.ErrorPath {
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

			pos := goSSA.Fset.Position(call.Pos())
			origin := ttypes.Location{
				File:     loader.RelativePath(pos.Filename, modulePath),
				Line:     pos.Line,
				Function: fn.Name(),
				Package:  packagePath(fn),
			}

			handlers, dropped := traceErrorValue(goSSA, modulePath, call, fn)

			path := ttypes.ErrorPath{
				Origin:   origin,
				Handlers: handlers,
				Dropped:  dropped,
				FailMode: inferFailMode(dropped),
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

	calleeName := callee.Name()
	calleePkg := ""
	if callee.Package() != nil {
		calleePkg = callee.Package().Pkg.Path()
	}

	for _, creator := range errorCreators {
		if calleeName == creator.funcName && strings.HasSuffix(calleePkg, creator.pkgSuffix) {
			return true
		}
	}

	return false
}

func traceErrorValue(goSSA *ir.GoSSAData, modulePath string, errorVal ssa.Value, fn *ssa.Function) ([]ttypes.ErrorHandler, bool) {
	var handlers []ttypes.ErrorHandler
	dropped := true

	refs := errorVal.Referrers()
	if refs == nil {
		return handlers, true
	}

	for _, ref := range *refs {
		pos := goSSA.Fset.Position(ref.Pos())
		loc := ttypes.Location{
			File:     loader.RelativePath(pos.Filename, modulePath),
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
			} else {
				// The error is passed as an argument to some function (even if we
				// don't recognize it as logging/wrapping). This means the error is
				// not silently dropped; the callee is responsible for it.
				dropped = false
			}

		case *ssa.Extract:
			subRefs := r.Referrers()
			if subRefs == nil || len(*subRefs) == 0 {
				handlers = append(handlers, ttypes.ErrorHandler{Location: loc, Kind: "DROP"})
			} else {
				// Trace through Extract one level to see if the extracted value is used.
				extractUsed := false
				for _, subRef := range *subRefs {
					if _, ok := subRef.(*ssa.DebugRef); ok {
						continue
					}
					extractUsed = true
					// Trace one level through calls on extracted values.
					if subCall, ok := subRef.(*ssa.Call); ok {
						callee := subCall.Call.StaticCallee()
						if callee != nil && isLoggingFunction(callee.Name()) {
							subPos := goSSA.Fset.Position(subCall.Pos())
							handlers = append(handlers, ttypes.ErrorHandler{
								Location: ttypes.Location{
									File:     loader.RelativePath(subPos.Filename, modulePath),
									Line:     subPos.Line,
									Function: fn.Name(),
									Package:  packagePath(fn),
								},
								Kind: "LOG",
							})
						}
					}
				}
				if extractUsed {
					dropped = false
				}
			}

		case *ssa.Store:
			// Store means the error is being persisted somewhere (assigned to a
			// variable, struct field, etc.). This counts as handling.
			dropped = false
			storeAddr := r.Addr
			if storeAddr != nil {
				addrRefs := storeAddr.Referrers()
				if addrRefs != nil {
					for _, addrRef := range *addrRefs {
						if ret, ok := addrRef.(*ssa.Return); ok {
							retPos := goSSA.Fset.Position(ret.Pos())
							handlers = append(handlers, ttypes.ErrorHandler{
								Location: ttypes.Location{
									File:     loader.RelativePath(retPos.Filename, modulePath),
									Line:     retPos.Line,
									Function: fn.Name(),
									Package:  packagePath(fn),
								},
								Kind: "RETURN",
							})
						}
					}
				}
			}

		case *ssa.Phi:
			dropped = false

		case *ssa.DebugRef:
			// ignore debug refs
		}
	}

	return handlers, dropped
}

// knownLogFunctions is the exact set of recognized logging function names.
// Using exact matches avoids false positives from prefix matching (e.g.
// "Error" the method vs "Errorf" the logger).
var knownLogFunctions = map[string]bool{
	// Standard log package
	"Printf": true, "Println": true, "Print": true,
	"Fatalf": true, "Fatalln": true, "Fatal": true,
	// Structured loggers (logr, zap, zerolog, slog)
	"Info": true, "Infof": true, "Infow": true,
	"Error": true, "Errorf": true, "Errorw": true,
	"Warn": true, "Warnf": true, "Warnw": true,
	"Debug": true, "Debugf": true, "Debugw": true,
	"Log": true, "WithError": true,
}

func isLoggingFunction(name string) bool {
	return knownLogFunctions[name]
}

// knownWrappingFunctions is the exact set of recognized error wrapping function names.
// Using exact matches avoids false positives (e.g. "Unwrap" matching "wrap" substring).
var knownWrappingFunctions = map[string]bool{
	"Wrap":        true,
	"Wrapf":       true,
	"WithMessage": true,
	"WithStack":   true,
	"Errorf":      true,
}

func isWrappingFunction(name string) bool {
	return knownWrappingFunctions[name]
}

// inferFailMode determines whether a dropped error leads to fail-open or fail-closed behavior.
// If the error is dropped (not returned, logged, or wrapped), the function continues
// executing past the error point, which is fail-open. If the error is handled
// (returned, logged, wrapped), the caller has the opportunity to react, which is fail-closed.
func inferFailMode(dropped bool) string {
	if dropped {
		return "OPEN"
	}
	return "CLOSED"
}

func packagePath(fn *ssa.Function) string {
	if fn.Package() != nil {
		return fn.Package().Pkg.Path()
	}
	return ""
}

// indentLevel returns the number of leading whitespace characters in a line.
func indentLevel(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// relativePath computes a relative path from rootDir. If rootDir is empty or
// the computation fails, the original path is returned.
func relativePath(rootDir, filePath string) string {
	if rootDir == "" {
		return filePath
	}
	rel, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return filePath
	}
	return rel
}

