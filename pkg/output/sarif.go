package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
	toolInfoURI  = "https://github.com/ugiordan/trust-flow-analyzer"
	toolName     = "trust-flow-analyzer"
)

// SARIF 2.1.0 types.

// SARIFLog is the top-level SARIF container.
type SARIFLog struct {
	Version string    `json:"version"`
	Schema  string    `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single invocation of a tool.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the tool that produced the results.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver describes the primary component of the tool.
type SARIFDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule describes a reporting descriptor (rule).
type SARIFRule struct {
	ID               string       `json:"id"`
	ShortDescription SARIFMessage `json:"shortDescription"`
	Help             SARIFMessage `json:"help,omitempty"`
}

// SARIFResult represents a single finding.
type SARIFResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    SARIFMessage      `json:"message"`
	Locations  []SARIFLocation   `json:"locations,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// SARIFMessage wraps a plain text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation identifies where a result was found.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

// SARIFPhysicalLocation identifies a file and optional region.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           *SARIFRegion          `json:"region,omitempty"`
}

// SARIFArtifactLocation identifies a file by URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// SARIFRegion identifies a line within a file.
type SARIFRegion struct {
	StartLine int `json:"startLine"`
}

// WriteSARIF writes the analysis result as a SARIF 2.1.0 JSON document.
func WriteSARIF(w io.Writer, result *types.AnalysisResult, version string) error {
	var results []SARIFResult
	rules := make(map[string]SARIFRule)
	project := result.Project

	// 1. Contradictions
	for _, c := range result.Contradictions {
		ruleID := "TFA-CONTRADICTION-" + strings.ToUpper(c.Severity)
		level := severityToLevel(c.Severity)
		ensureRule(rules, ruleID, "Trust assumption contradiction ("+strings.ToUpper(c.Severity)+")")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("%s: %s", c.ID, c.Title)},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Contradiction",
				"trust-flow-analyzer/project": project,
			},
		}
		if len(c.Assumptions) > 0 {
			r.Locations = []SARIFLocation{locationFromTypes(c.Assumptions[0].Location)}
		}
		results = append(results, r)
	}

	// 2. Auth flows with PERMISSIVE posture
	for _, af := range result.AuthFlows {
		if af.Posture != "PERMISSIVE" {
			continue
		}
		ruleID := "TFA-AUTH-PERMISSIVE"
		ensureRule(rules, ruleID, "Authentication flow with permissive posture")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "warning",
			Message: SARIFMessage{Text: fmt.Sprintf("Auth flow %q has PERMISSIVE posture", af.Name)},
			Locations: []SARIFLocation{
				locationFromTypes(af.Entry),
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "AuthFlow",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 3. Contract violations
	for _, ct := range result.Contracts {
		for _, v := range ct.Violations {
			ruleID := "TFA-CONTRACT-" + strings.ReplaceAll(v.Kind, " ", "-")
			ensureRule(rules, ruleID, "Contract violation: "+v.Kind)

			r := SARIFResult{
				RuleID:  ruleID,
				Level:   "warning",
				Message: SARIFMessage{Text: v.Description},
				Locations: []SARIFLocation{
					locationFromTypes(v.Caller),
				},
				Properties: map[string]string{
					"trust-flow-analyzer/pass":    "Contract",
					"trust-flow-analyzer/project": project,
				},
			}
			results = append(results, r)
		}
	}

	// 4. Dropped error paths
	for _, ep := range result.ErrorPaths {
		if !ep.Dropped {
			continue
		}
		ruleID := "TFA-ERROR-DROPPED"
		ensureRule(rules, ruleID, "Error value dropped without handling")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "error",
			Message: SARIFMessage{Text: fmt.Sprintf("Error dropped at %s:%s (fail mode: %s)", ep.Origin.File, ep.Origin.Function, ep.FailMode)},
			Locations: []SARIFLocation{
				locationFromTypes(ep.Origin),
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "ErrorProp",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 5. RBAC findings
	for _, rb := range result.RBACFindings {
		ruleID := "TFA-RBAC-" + strings.ToUpper(rb.Severity)
		level := severityToLevel(rb.Severity)
		ensureRule(rules, ruleID, "RBAC finding ("+strings.ToUpper(rb.Severity)+")")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("%s (%s): %s", rb.Name, rb.Rule, rb.Reason)},
			Locations: []SARIFLocation{
				locationFromFile(rb.File),
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "RBAC",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 6. Template risks
	for _, tr := range result.TemplateRisks {
		kind := strings.ReplaceAll(strings.ToUpper(tr.Kind), " ", "-")
		ruleID := "TFA-TEMPLATE-" + kind
		level := severityToLevel(tr.Severity)
		ensureRule(rules, ruleID, "Template risk: "+tr.Kind)

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: tr.Description},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: tr.File},
						Region:           &SARIFRegion{StartLine: tr.Line},
					},
				},
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Template",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 7. Uncovered routes
	for _, rc := range result.RouteCoverage {
		if rc.Covered || strings.ToUpper(rc.Mechanism) == "INTENTIONAL" {
			continue
		}
		ruleID := "TFA-ROUTE-UNCOVERED"
		ensureRule(rules, ruleID, "Route without auth policy coverage")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "warning",
			Message: SARIFMessage{Text: fmt.Sprintf("Route %s (%s) has no auth policy coverage", rc.Route, rc.RouteKind)},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "AuthPolicy",
				"trust-flow-analyzer/project": project,
			},
		}
		if rc.RouteFile != "" {
			r.Locations = []SARIFLocation{locationFromFile(rc.RouteFile)}
		}
		results = append(results, r)
	}

	// 8. Weak mTLS policies (PERMISSIVE or DISABLE)
	for _, mp := range result.MeshPolicies {
		mode := strings.ToUpper(mp.MTLSMode)
		if mode != "PERMISSIVE" && mode != "DISABLE" {
			continue
		}
		ruleID := "TFA-MTLS-" + mode
		ensureRule(rules, ruleID, "Weak mTLS mode: "+mode)

		level := "warning"
		if mode == "DISABLE" {
			level = "error"
		}

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("%s (%s) has mTLS mode %s (%s)", mp.Name, mp.Kind, mp.MTLSMode, mp.Scope)},
			Locations: []SARIFLocation{
				locationFromFile(mp.File),
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "MeshPolicy",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 9. Secret exposures
	for _, se := range result.SecretExposures {
		pattern := strings.ReplaceAll(strings.ToUpper(se.Pattern), " ", "-")
		ruleID := "TFA-SECRET-" + pattern
		ensureRule(rules, ruleID, "Secret exposure: "+se.Pattern)

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "error",
			Message: SARIFMessage{Text: se.Description},
			Locations: []SARIFLocation{
				locationFromTypes(se.Location),
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Secrets",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 10. Orphanable resources
	for _, lc := range result.Lifecycles {
		if !lc.Orphanable {
			continue
		}
		ruleID := "TFA-LIFECYCLE-ORPHANABLE"
		ensureRule(rules, ruleID, "Resource can be orphaned (no owner reference or finalizer)")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "warning",
			Message: SARIFMessage{Text: fmt.Sprintf("Resource %s can be orphaned: no owner reference or finalizer", lc.Resource)},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Lifecycle",
				"trust-flow-analyzer/project": project,
			},
		}
		if lc.Create != nil {
			r.Locations = []SARIFLocation{locationFromTypes(*lc.Create)}
		}
		results = append(results, r)
	}

	// 11. Webhook defaults with unset security fields
	for _, wd := range result.WebhookDefaults {
		if len(wd.FieldsUnset) == 0 {
			continue
		}
		ruleID := "TFA-WEBHOOK-UNSET"
		ensureRule(rules, ruleID, "Webhook defaulter does not set security-relevant fields")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "warning",
			Message: SARIFMessage{Text: fmt.Sprintf("%s does not set: %s", wd.Function, strings.Join(wd.FieldsUnset, ", "))},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: wd.File},
						Region:           &SARIFRegion{StartLine: wd.Line},
					},
				},
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Webhook",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 12. Webhook validations with unchecked security fields
	for _, wv := range result.WebhookValidations {
		if len(wv.FieldsUnchecked) == 0 {
			continue
		}
		ruleID := "TFA-WEBHOOK-VALIDATION-GAP"
		ensureRule(rules, ruleID, "Webhook validator does not check security-relevant fields")

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   "warning",
			Message: SARIFMessage{Text: fmt.Sprintf("%s does not check: %s", wv.Function, strings.Join(wv.FieldsUnchecked, ", "))},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{URI: wv.File},
						Region:           &SARIFRegion{StartLine: wv.Line},
					},
				},
			},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":    "Webhook",
				"trust-flow-analyzer/project": project,
			},
		}
		results = append(results, r)
	}

	// 13. Posture check failures
	for _, pc := range result.PostureChecks {
		if pc.Status == "PASS" || pc.Status == "N/A" {
			continue
		}
		ruleID := "TFA-POSTURE-" + strings.ToUpper(pc.Status)
		ensureRule(rules, ruleID, "Security posture check: "+pc.Status)

		level := "note"
		if pc.Status == "FAIL" {
			level = severityToLevel(pc.Severity)
		}

		r := SARIFResult{
			RuleID:  ruleID,
			Level:   level,
			Message: SARIFMessage{Text: fmt.Sprintf("[%s] %s: %s", pc.Status, pc.Name, pc.Details)},
			Properties: map[string]string{
				"trust-flow-analyzer/pass":     "Posture",
				"trust-flow-analyzer/project":  project,
				"trust-flow-analyzer/category": pc.Category,
			},
		}
		results = append(results, r)
	}

	// Collect unique rules in stable order (insertion order via slice).
	var ruleSlice []SARIFRule
	seen := make(map[string]bool)
	for _, r := range results {
		if !seen[r.RuleID] {
			seen[r.RuleID] = true
			ruleSlice = append(ruleSlice, rules[r.RuleID])
		}
	}

	if results == nil {
		results = []SARIFResult{}
	}
	if ruleSlice == nil {
		ruleSlice = []SARIFRule{}
	}

	log := SARIFLog{
		Version: sarifVersion,
		Schema:  sarifSchema,
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           toolName,
						InformationURI: toolInfoURI,
						Version:        version,
						Rules:          ruleSlice,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// severityToLevel maps trust-flow-analyzer severity strings to SARIF levels.
func severityToLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "MINOR":
		return "note"
	default:
		return "warning"
	}
}

// ensureRule adds a rule to the map if it does not already exist.
func ensureRule(rules map[string]SARIFRule, id, description string) {
	if _, ok := rules[id]; !ok {
		rules[id] = SARIFRule{
			ID:               id,
			ShortDescription: SARIFMessage{Text: description},
		}
	}
}

// locationFromTypes builds a SARIFLocation from a types.Location.
func locationFromTypes(loc types.Location) SARIFLocation {
	sl := SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: loc.File},
		},
	}
	if loc.Line > 0 {
		sl.PhysicalLocation.Region = &SARIFRegion{StartLine: loc.Line}
	}
	return sl
}

// locationFromFile builds a SARIFLocation from just a file path (no line info).
func locationFromFile(file string) SARIFLocation {
	return SARIFLocation{
		PhysicalLocation: SARIFPhysicalLocation{
			ArtifactLocation: SARIFArtifactLocation{URI: file},
		},
	}
}
