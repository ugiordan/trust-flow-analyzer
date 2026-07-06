package treesitter

import (
	"path/filepath"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
)

// BuildCallGraph produces heuristic caller/callee maps from extracted functions and
// call sites. The algorithm mirrors architecture-analyzer's resolveCallEdges:
//
//  1. Build an index: map[shortName][]FunctionInfo
//  2. Build a package index: map[dir]map[shortName][]FunctionInfo
//  3. For each CallSiteInfo, resolve the callee by short name:
//     - Unqualified calls match within the same directory first
//     - Qualified calls (dotted) try same directory, then cross-directory
//  4. Produce callees map[callerID][]calleeID and callers map[calleeID][]callerID
func BuildCallGraph(functions []ir.FunctionInfo, callSites []ir.CallSiteInfo) (callees map[string][]string, callers map[string][]string) {
	callees = make(map[string][]string)
	callers = make(map[string][]string)

	if len(functions) == 0 || len(callSites) == 0 {
		return callees, callers
	}

	// Index 1: short function name -> all matching functions
	fnByName := make(map[string][]ir.FunctionInfo)
	for _, fn := range functions {
		fnByName[fn.Name] = append(fnByName[fn.Name], fn)
	}

	// Index 2: directory -> short name -> functions in that directory
	pkgIndex := make(map[string]map[string][]ir.FunctionInfo)
	for _, fn := range functions {
		dir := filepath.Dir(fn.File)
		if pkgIndex[dir] == nil {
			pkgIndex[dir] = make(map[string][]ir.FunctionInfo)
		}
		pkgIndex[dir][fn.Name] = append(pkgIndex[dir][fn.Name], fn)
	}

	// Resolve each call site
	for _, cs := range callSites {
		callerID := cs.CallerFuncID
		if callerID == "" {
			// Module-level call with no enclosing function, skip
			continue
		}

		callName := cs.CalleeName
		parts := strings.Split(callName, ".")
		shortName := parts[len(parts)-1]
		isQualified := len(parts) > 1

		csDir := filepath.Dir(cs.File)

		var matched []ir.FunctionInfo

		if !isQualified {
			// Unqualified call (e.g., "do_stuff"): match within same directory only
			if pkgFns, ok := pkgIndex[csDir]; ok {
				matched = pkgFns[shortName]
			}
		} else {
			// Qualified call (e.g., "auth.verify_token" or "self.process"):
			// prefer same-directory matches, fall back to cross-directory
			if pkgFns, ok := pkgIndex[csDir]; ok {
				matched = pkgFns[shortName]
			}
			if len(matched) == 0 {
				matched = fnByName[shortName]
			}
		}

		// Record edges (deduplicated per caller-callee pair)
		for _, target := range matched {
			// Skip self-edges
			if target.ID == callerID {
				continue
			}
			callees[callerID] = appendUnique(callees[callerID], target.ID)
			callers[target.ID] = appendUnique(callers[target.ID], callerID)
		}
	}

	return callees, callers
}

// appendUnique appends val to slice only if it is not already present.
func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
