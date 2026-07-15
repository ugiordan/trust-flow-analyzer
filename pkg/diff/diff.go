package diff

import (
	"fmt"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// DiffResult holds the comparison between a baseline and a current analysis.
type DiffResult struct {
	New       []DiffFinding // findings in current but not in baseline
	Removed   []DiffFinding // findings in baseline but not in current
	Changed   []DiffChange  // findings that changed severity
	Unchanged int           // count of unchanged findings
}

// DiffFinding is a normalized finding suitable for comparison across runs.
type DiffFinding struct {
	Category string // contradiction, rbac, template, route, etc.
	Key      string // stable identifier for matching
	Summary  string // human-readable summary
	Severity string // HIGH, MEDIUM, LOW
	File     string
	Line     int
}

// DiffChange represents a finding whose severity changed between runs.
type DiffChange struct {
	Finding     DiffFinding
	OldSeverity string
	NewSeverity string
}

// HasNew returns true if there are any new or worsened findings.
func (d *DiffResult) HasNew() bool {
	if len(d.New) > 0 {
		return true
	}
	for _, c := range d.Changed {
		if severityRank(c.NewSeverity) > severityRank(c.OldSeverity) {
			return true
		}
	}
	return false
}

// Compare compares a baseline and current AnalysisResult, returning the diff.
func Compare(baseline, current *types.AnalysisResult) *DiffResult {
	baseFindings := Flatten(baseline)
	currFindings := Flatten(current)

	baseMap := make(map[string]DiffFinding, len(baseFindings))
	for _, f := range baseFindings {
		baseMap[f.Key] = f
	}

	currMap := make(map[string]DiffFinding, len(currFindings))
	for _, f := range currFindings {
		currMap[f.Key] = f
	}

	result := &DiffResult{}

	// New and changed findings: in current but not in baseline, or severity differs.
	for key, curr := range currMap {
		base, exists := baseMap[key]
		if !exists {
			result.New = append(result.New, curr)
			continue
		}
		if !strings.EqualFold(curr.Severity, base.Severity) {
			result.Changed = append(result.Changed, DiffChange{
				Finding:     curr,
				OldSeverity: base.Severity,
				NewSeverity: curr.Severity,
			})
		} else {
			result.Unchanged++
		}
	}

	// Removed findings: in baseline but not in current.
	for key, base := range baseMap {
		if _, exists := currMap[key]; !exists {
			result.Removed = append(result.Removed, base)
		}
	}

	return result
}

// Flatten extracts all security-relevant findings from an AnalysisResult into
// a normalized list of DiffFindings with stable keys for comparison.
func Flatten(result *types.AnalysisResult) []DiffFinding {
	var findings []DiffFinding

	// Contradictions already subsume rbac, template, and mtls raw findings
	// (detectRBACFindings, detectTemplateRisks, detectWeakMTLS convert them).
	// Track which categories are represented by contradictions so we skip the
	// raw entries below and avoid double-counting.
	hasContradictions := len(result.Contradictions) > 0

	// Contradictions
	for _, c := range result.Contradictions {
		file := ""
		line := 0
		if len(c.Assumptions) > 0 {
			file = c.Assumptions[0].Location.File
			line = c.Assumptions[0].Location.Line
		}
		findings = append(findings, DiffFinding{
			Category: "contradiction",
			Key:      fmt.Sprintf("contradiction:%s", c.Title),
			Summary:  fmt.Sprintf("%s: %s", c.ID, c.Title),
			Severity: strings.ToUpper(c.Severity),
			File:     file,
			Line:     line,
		})
	}

	// Auth flows (only PERMISSIVE posture is a finding)
	for _, af := range result.AuthFlows {
		if af.Posture != "PERMISSIVE" {
			continue
		}
		findings = append(findings, DiffFinding{
			Category: "authflow",
			Key:      fmt.Sprintf("authflow:%s", af.Name),
			Summary:  fmt.Sprintf("Auth flow %q has PERMISSIVE posture", af.Name),
			Severity: "MEDIUM",
			File:     af.Entry.File,
			Line:     af.Entry.Line,
		})
	}

	// Contract violations
	for _, ct := range result.Contracts {
		for _, v := range ct.Violations {
			findings = append(findings, DiffFinding{
				Category: "contract",
				Key:      fmt.Sprintf("contract:%s:%s:%s", ct.Function.File, ct.Function.Function, v.Caller.Function),
				Summary:  v.Description,
				Severity: "MEDIUM",
				File:     v.Caller.File,
				Line:     v.Caller.Line,
			})
		}
	}

	// Dropped error paths
	for _, ep := range result.ErrorPaths {
		if !ep.Dropped {
			continue
		}
		findings = append(findings, DiffFinding{
			Category: "error",
			Key:      fmt.Sprintf("error:%s:%d", ep.Origin.File, ep.Origin.Line),
			Summary:  fmt.Sprintf("Error dropped at %s:%s (fail mode: %s)", ep.Origin.File, ep.Origin.Function, ep.FailMode),
			Severity: "HIGH",
			File:     ep.Origin.File,
			Line:     ep.Origin.Line,
		})
	}

	// RBAC findings: skip when contradictions exist (already represented there).
	if !hasContradictions {
		for _, rb := range result.RBACFindings {
			findings = append(findings, DiffFinding{
				Category: "rbac",
				Key:      fmt.Sprintf("rbac:%s:%s", rb.Name, rb.Rule),
				Summary:  fmt.Sprintf("%s (%s): %s", rb.Name, rb.Rule, rb.Reason),
				Severity: strings.ToUpper(rb.Severity),
				File:     rb.File,
			})
		}
	}

	// Template risks: skip when contradictions exist (already represented there).
	if !hasContradictions {
		for _, tr := range result.TemplateRisks {
			findings = append(findings, DiffFinding{
				Category: "template",
				Key:      fmt.Sprintf("template:%s:%d:%s", tr.File, tr.Line, tr.Kind),
				Summary:  tr.Description,
				Severity: strings.ToUpper(tr.Severity),
				File:     tr.File,
				Line:     tr.Line,
			})
		}
	}

	// Uncovered routes
	for _, rc := range result.RouteCoverage {
		if rc.Covered || strings.EqualFold(rc.Mechanism, "INTENTIONAL") {
			continue
		}
		findings = append(findings, DiffFinding{
			Category: "route",
			Key:      fmt.Sprintf("route:%s", rc.Route),
			Summary:  fmt.Sprintf("Route %s (%s) has no auth policy coverage", rc.Route, rc.RouteKind),
			Severity: "MEDIUM",
			File:     rc.RouteFile,
		})
	}

	// Weak mTLS policies: skip when contradictions exist (already represented there).
	if !hasContradictions {
		for _, mp := range result.MeshPolicies {
			mode := strings.ToUpper(mp.MTLSMode)
			if mode != "PERMISSIVE" && mode != "DISABLE" {
				continue
			}
			sev := "MEDIUM"
			if mode == "DISABLE" {
				sev = "HIGH"
			}
			findings = append(findings, DiffFinding{
				Category: "mtls",
				Key:      fmt.Sprintf("mtls:%s:%s", mp.Name, mp.MTLSMode),
				Summary:  fmt.Sprintf("%s (%s) has mTLS mode %s (%s)", mp.Name, mp.Kind, mp.MTLSMode, mp.Scope),
				Severity: sev,
				File:     mp.File,
			})
		}
	}

	// Secret exposures
	for _, se := range result.SecretExposures {
		findings = append(findings, DiffFinding{
			Category: "secret",
			Key:      fmt.Sprintf("secret:%s:%d", se.Location.File, se.Location.Line),
			Summary:  se.Description,
			Severity: "HIGH",
			File:     se.Location.File,
			Line:     se.Location.Line,
		})
	}

	// Orphanable resources
	for _, lc := range result.Lifecycles {
		if !lc.Orphanable {
			continue
		}
		file := ""
		line := 0
		if lc.Create != nil {
			file = lc.Create.File
			line = lc.Create.Line
		}
		findings = append(findings, DiffFinding{
			Category: "lifecycle",
			Key:      fmt.Sprintf("lifecycle:%s", lc.Resource),
			Summary:  fmt.Sprintf("Resource %s can be orphaned: no owner reference or finalizer", lc.Resource),
			Severity: "LOW",
			File:     file,
			Line:     line,
		})
	}

	// Webhook defaults with unset security fields
	for _, wd := range result.WebhookDefaults {
		if len(wd.FieldsUnset) == 0 {
			continue
		}
		findings = append(findings, DiffFinding{
			Category: "webhook",
			Key:      fmt.Sprintf("webhook:%s", wd.Function),
			Summary:  fmt.Sprintf("%s does not set: %s", wd.Function, strings.Join(wd.FieldsUnset, ", ")),
			Severity: "MEDIUM",
			File:     wd.File,
			Line:     wd.Line,
		})
	}

	// Webhook validations with unchecked security fields
	for _, wv := range result.WebhookValidations {
		if len(wv.FieldsUnchecked) == 0 {
			continue
		}
		findings = append(findings, DiffFinding{
			Category: "webhook-validation",
			Key:      fmt.Sprintf("webhook-validation:%s", wv.Function),
			Summary:  fmt.Sprintf("%s does not check: %s", wv.Function, strings.Join(wv.FieldsUnchecked, ", ")),
			Severity: "LOW",
			File:     wv.File,
			Line:     wv.Line,
		})
	}

	// Posture check failures
	for _, pc := range result.PostureChecks {
		if pc.Status == "PASS" || pc.Status == "N/A" {
			continue
		}
		sev := "LOW"
		if pc.Status == "FAIL" && pc.Severity != "" {
			sev = strings.ToUpper(pc.Severity)
		}
		findings = append(findings, DiffFinding{
			Category: "posture",
			Key:      fmt.Sprintf("posture:%s", pc.Name),
			Summary:  fmt.Sprintf("[%s] %s: %s", pc.Status, pc.Name, pc.Details),
			Severity: sev,
		})
	}

	return findings
}

// severityRank returns a numeric rank for severity comparison.
// Higher rank means more severe.
func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}
