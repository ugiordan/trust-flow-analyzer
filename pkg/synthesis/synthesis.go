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

	for i := range contradictions {
		contradictions[i].ID = fmt.Sprintf("CONTRADICTION-%03d", i+1)
	}

	sort.Slice(contradictions, func(i, j int) bool {
		return contradictions[i].ID < contradictions[j].ID
	})

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

		assumptions := []types.Assumption{
			{
				Location:    flow.Authentication.Location,
				Description: flow.Authentication.Location.Function + " authenticates the request",
			},
			{
				Location:    flow.Entry,
				Description: flow.Entry.Function + " assumes downstream authorization exists",
			},
		}

		if flow.Authorization != nil {
			assumptions = append(assumptions, types.Assumption{
				Location:    flow.Authorization.Location,
				Description: flow.Authorization.Location.Function + " authorization gate exists but may be permissive by default",
			})
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

func detectDroppedErrorsOnAuthPath(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	authPackages := make(map[string]bool)
	for _, flow := range result.AuthFlows {
		if flow.Authentication != nil {
			authPackages[flow.Authentication.Location.Package] = true
		}
		if flow.Authorization != nil {
			authPackages[flow.Authorization.Location.Package] = true
		}
	}

	for _, ep := range result.ErrorPaths {
		if !ep.Dropped {
			continue
		}
		if !authPackages[ep.Origin.Package] {
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

func detectOrphanedResources(result *types.AnalysisResult) []types.Contradiction {
	var contradictions []types.Contradiction

	for _, lc := range result.Lifecycles {
		if !lc.Orphanable {
			continue
		}

		assumptions := []types.Assumption{
			{
				Location:    lc.Create,
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
