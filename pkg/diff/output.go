package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// WriteText writes the diff result in a human-readable text format.
func WriteText(w io.Writer, d *DiffResult) error {
	fmt.Fprintln(w, "## Trust Flow Diff")
	fmt.Fprintln(w)

	// Sort findings by severity (HIGH first) for consistent output.
	sortFindings(d.New)
	sortFindings(d.Removed)

	// New findings
	fmt.Fprintf(w, "### New findings (%d)\n", len(d.New))
	if len(d.New) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		for _, f := range d.New {
			loc := formatLocation(f.File, f.Line)
			fmt.Fprintf(w, "- [%s] %s: %s%s\n", f.Severity, capitalize(f.Category), f.Summary, loc)
		}
	}
	fmt.Fprintln(w)

	// Removed findings
	fmt.Fprintf(w, "### Removed findings (%d)\n", len(d.Removed))
	if len(d.Removed) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		for _, f := range d.Removed {
			loc := formatLocation(f.File, f.Line)
			fmt.Fprintf(w, "- [%s] %s: %s%s (fixed)\n", f.Severity, capitalize(f.Category), f.Summary, loc)
		}
	}
	fmt.Fprintln(w)

	// Changed severity
	fmt.Fprintf(w, "### Changed severity (%d)\n", len(d.Changed))
	if len(d.Changed) == 0 {
		fmt.Fprintln(w, "None")
	} else {
		for _, c := range d.Changed {
			loc := formatLocation(c.Finding.File, c.Finding.Line)
			fmt.Fprintf(w, "- %s: %s: %s -> %s%s\n", capitalize(c.Finding.Category), c.Finding.Summary, c.OldSeverity, c.NewSeverity, loc)
		}
	}
	fmt.Fprintln(w)

	// Summary
	baselineTotal := len(d.Removed) + d.Unchanged + len(d.Changed)
	currentTotal := len(d.New) + d.Unchanged + len(d.Changed)
	fmt.Fprintf(w, "### Summary\n")
	fmt.Fprintf(w, "Baseline: %d findings | Current: %d findings | New: %d | Removed: %d | Changed: %d\n",
		baselineTotal, currentTotal, len(d.New), len(d.Removed), len(d.Changed))

	return nil
}

// DiffJSON is the JSON-serializable form of a DiffResult.
type DiffJSON struct {
	New       []DiffFinding `json:"new"`
	Removed   []DiffFinding `json:"removed"`
	Changed   []DiffChange  `json:"changed"`
	Unchanged int           `json:"unchanged"`
	Summary   DiffSummary   `json:"summary"`
}

// DiffSummary contains aggregate counts for JSON output.
type DiffSummary struct {
	BaselineTotal int `json:"baseline_total"`
	CurrentTotal  int `json:"current_total"`
	NewCount      int `json:"new_count"`
	RemovedCount  int `json:"removed_count"`
	ChangedCount  int `json:"changed_count"`
}

// WriteJSON writes the diff result as indented JSON.
func WriteJSON(w io.Writer, d *DiffResult) error {
	baselineTotal := len(d.Removed) + d.Unchanged + len(d.Changed)
	currentTotal := len(d.New) + d.Unchanged + len(d.Changed)

	changed := d.Changed
	if changed == nil {
		changed = []DiffChange{}
	}

	out := DiffJSON{
		New:       nonNil(d.New),
		Removed:   nonNil(d.Removed),
		Changed:   changed,
		Unchanged: d.Unchanged,
		Summary: DiffSummary{
			BaselineTotal: baselineTotal,
			CurrentTotal:  currentTotal,
			NewCount:      len(d.New),
			RemovedCount:  len(d.Removed),
			ChangedCount:  len(d.Changed),
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// WriteSARIF writes the diff result as a SARIF 2.1.0 document.
// Only new findings are emitted as SARIF results (removed/changed are properties).
func WriteSARIF(w io.Writer, d *DiffResult, version string) error {
	type sarifMessage struct {
		Text string `json:"text"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine"`
	}
	type sarifArtifactLocation struct {
		URI string `json:"uri"`
	}
	type sarifPhysicalLocation struct {
		ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
		Region           *sarifRegion          `json:"region,omitempty"`
	}
	type sarifLocation struct {
		PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID     string            `json:"ruleId"`
		Level      string            `json:"level"`
		Message    sarifMessage      `json:"message"`
		Locations  []sarifLocation   `json:"locations,omitempty"`
		Properties map[string]string `json:"properties,omitempty"`
	}
	type sarifRule struct {
		ID               string       `json:"id"`
		ShortDescription sarifMessage `json:"shortDescription"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		InformationURI string      `json:"informationUri"`
		Version        string      `json:"version"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifLog struct {
		Version string     `json:"version"`
		Schema  string     `json:"$schema"`
		Runs    []sarifRun `json:"runs"`
	}

	var results []sarifResult
	rules := make(map[string]sarifRule)

	for _, f := range d.New {
		ruleID := fmt.Sprintf("TFA-DIFF-NEW-%s", strings.ToUpper(f.Category))
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = sarifRule{
				ID:               ruleID,
				ShortDescription: sarifMessage{Text: fmt.Sprintf("New %s finding", f.Category)},
			}
		}

		r := sarifResult{
			RuleID:  ruleID,
			Level:   severityToSARIFLevel(f.Severity),
			Message: sarifMessage{Text: f.Summary},
			Properties: map[string]string{
				"trust-flow-analyzer/diff": "new",
				"trust-flow-analyzer/category": f.Category,
			},
		}
		if f.File != "" {
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: f.File},
				},
			}
			if f.Line > 0 {
				loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Line}
			}
			r.Locations = []sarifLocation{loc}
		}
		results = append(results, r)
	}

	// Collect rules in stable order.
	var ruleSlice []sarifRule
	seen := make(map[string]bool)
	for _, r := range results {
		if !seen[r.RuleID] {
			seen[r.RuleID] = true
			ruleSlice = append(ruleSlice, rules[r.RuleID])
		}
	}

	if results == nil {
		results = []sarifResult{}
	}
	if ruleSlice == nil {
		ruleSlice = []sarifRule{}
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "trust-flow-analyzer-diff",
						InformationURI: "https://github.com/ugiordan/trust-flow-analyzer",
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

func formatLocation(file string, line int) string {
	if file == "" {
		return ""
	}
	if line > 0 {
		return fmt.Sprintf(" at %s:%d", file, line)
	}
	return fmt.Sprintf(" in %s", file)
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func sortFindings(findings []DiffFinding) {
	sort.Slice(findings, func(i, j int) bool {
		ri := severityRank(findings[i].Severity)
		rj := severityRank(findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return findings[i].Key < findings[j].Key
	})
}

func nonNil(findings []DiffFinding) []DiffFinding {
	if findings == nil {
		return []DiffFinding{}
	}
	return findings
}

func severityToSARIFLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW":
		return "note"
	default:
		return "warning"
	}
}
