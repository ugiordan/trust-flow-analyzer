package synthesis

import (
	"fmt"
	"sort"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// Synthesize detects contradictions across the analysis results.
// It looks for patterns where components make incompatible assumptions
// about each other (assume-guarantee violations).
func Synthesize(result *types.AnalysisResult) {
	var contradictions []types.Contradiction

	contradictions = append(contradictions, detectAuthWithoutAuthz(result)...)
	contradictions = append(contradictions, detectPermissiveDefaults(result)...)
	contradictions = append(contradictions, detectDroppedErrorsOnAuthPath(result)...)
	contradictions = append(contradictions, detectOrphanedResources(result)...)
	contradictions = append(contradictions, detectUncoveredRoutes(result)...)

	// Sort by severity (HIGH > MEDIUM > LOW) then title for stable ordering,
	// then assign IDs so they are deterministic regardless of detection order.
	sort.Slice(contradictions, func(i, j int) bool {
		si, sj := severityRank(contradictions[i].Severity), severityRank(contradictions[j].Severity)
		if si != sj {
			return si < sj
		}
		return contradictions[i].Title < contradictions[j].Title
	})

	for i := range contradictions {
		contradictions[i].ID = fmt.Sprintf("CONTRADICTION-%03d", i+1)
	}

	result.Contradictions = contradictions
}

func detectAuthWithoutAuthz(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, flow := range result.AuthFlows {
		if flow.Posture != "PERMISSIVE" {
			continue
		}

		if flow.Authentication == nil {
			continue
		}

		// PERMISSIVE posture means authentication exists but authorization does not.
		// No need to check flow.Authorization here since it is always nil for this posture.
		assumptions := []types.Assumption{
			{
				Location:    flow.Authentication.Location,
				Description: flow.Authentication.Location.Function + " authenticates the request",
			},
			{
				Location:    flow.Entry,
				Description: flow.Entry.Function + " has no authorization gate after authentication",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       flow.Name + " path has no effective authorization gate",
			Assumptions: assumptions,
			Reality:     "Authentication success equals authorization. Any valid token grants access.",
			Severity:    "HIGH",
		})
	}

	return contradictions
}

func detectPermissiveDefaults(result *types.AnalysisResult) []types.Contradiction {
	var permissive []types.DefaultValue
	for _, d := range result.Defaults {
		if d.Permissiveness == "PERMISSIVE" {
			permissive = append(permissive, d)
		}
	}

	if len(permissive) < 2 {
		return nil
	}

	var assumptions []types.Assumption
	for _, d := range permissive {
		assumptions = append(assumptions, types.Assumption{
			Location:    d.Location,
			Description: d.Field + " defaults to " + d.LibraryDefault + " (" + d.PlatformMeaning + ")",
		})
	}

	return []types.Contradiction{
		{
			Title:       "Multiple security-critical fields default to permissive values",
			Assumptions: assumptions,
			Reality:     fmt.Sprintf("%d configuration fields default to permissive values. Combined effect may create an open access path.", len(permissive)),
			Severity:    "MEDIUM",
		},
	}
}

// functionKey produces a key identifying a function by package, name, and file
// (without line number). This is used for cross-referencing between analysis
// passes where the same function appears with different line numbers: auth flow
// locations use the function definition line, while error path origins use the
// error creation call-site line.
func functionKey(loc types.Location) string {
	return fmt.Sprintf("%s.%s@%s", loc.Package, loc.Function, loc.File)
}

func detectDroppedErrorsOnAuthPath(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	// Build a set of auth-related functions keyed by package.function@file.
	// Line numbers are excluded because auth locations use fn.Pos() (definition line)
	// while error origins use call.Pos() (call-site line within the function).
	authFunctions := make(map[string]bool)
	for _, flow := range result.AuthFlows {
		authFunctions[functionKey(flow.Entry)] = true
		if flow.Authentication != nil {
			authFunctions[functionKey(flow.Authentication.Location)] = true
		}
		if flow.Authorization != nil {
			authFunctions[functionKey(flow.Authorization.Location)] = true
		}
		for _, v := range flow.Validators {
			authFunctions[functionKey(v.Location)] = true
		}
	}

	for _, ep := range result.ErrorPaths {
		if !ep.Dropped {
			continue
		}
		funcKey := functionKey(ep.Origin)
		if !authFunctions[funcKey] {
			continue
		}

		contradictions = append(contradictions, types.Contradiction{
			Title: "Error in " + ep.Origin.Function + " silently dropped on auth path",
			Assumptions: []types.Assumption{
				{
					Location:    ep.Origin,
					Description: ep.Origin.Function + " creates an error that is never handled",
				},
			},
			Reality:  "Error on authentication/authorization path is dropped. Failure may silently allow access (fail-open: " + ep.FailMode + ").",
			Severity: "HIGH",
		})
	}

	return contradictions
}

func severityRank(s string) int {
	switch s {
	case "HIGH":
		return 0
	case "MEDIUM":
		return 1
	case "LOW":
		return 2
	default:
		return 3
	}
}

func detectUncoveredRoutes(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, cov := range result.RouteCoverage {
		if cov.Covered || cov.Mechanism == "INTENTIONAL" {
			continue
		}

		assumptions := []types.Assumption{
			{
				Location: types.Location{
					File: cov.RouteFile,
				},
				Description: cov.RouteKind + " " + cov.Route + " exposes backend " + cov.Backend + " without auth policy",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       cov.Route + " route has no auth policy coverage",
			Assumptions: assumptions,
			Reality:     "Route " + cov.Route + " in " + cov.RouteFile + " has no matching AuthPolicy, AuthConfig, or gateway-level default. Traffic to this route is unauthenticated.",
			Severity:    "MEDIUM",
			Mitigation:  "Add an AuthPolicy targeting the route or its parent gateway.",
		})
	}

	return contradictions
}

func detectOrphanedResources(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, lc := range result.Lifecycles {
		if !lc.Orphanable || lc.Create == nil {
			continue
		}

		assumptions := []types.Assumption{
			{
				Location:    *lc.Create,
				Description: lc.Create.Function + " creates " + lc.Resource + " without owner reference or finalizer",
			},
		}

		contradictions = append(contradictions, types.Contradiction{
			Title:       lc.Resource + " created without ownership or cleanup mechanism",
			Assumptions: assumptions,
			Reality:     "Resource " + lc.Resource + " has no owner reference or finalizer. If the parent is deleted, this resource will be orphaned.",
			Severity:    "LOW",
		})
	}

	return contradictions
}
