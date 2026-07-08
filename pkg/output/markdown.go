package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// WriteMarkdown writes the analysis result as a markdown trust flow map.
func WriteMarkdown(w io.Writer, result *types.AnalysisResult) error {
	p := &printer{w: w}

	p.line("# Trust Flow Map: %s", result.Project)
	p.blank()

	if len(result.AuthFlows) > 0 {
		writeAuthFlows(p, result.AuthFlows)
	}

	if len(result.Defaults) > 0 {
		writeDefaults(p, result.Defaults)
	}

	if len(result.Contracts) > 0 {
		writeContracts(p, result.Contracts)
	}

	if len(result.ErrorPaths) > 0 {
		writeErrorPaths(p, result.ErrorPaths)
	}

	if len(result.Lifecycles) > 0 {
		writeLifecycles(p, result.Lifecycles)
	}

	if len(result.SecretExposures) > 0 {
		writeSecretExposures(p, result.SecretExposures)
	}

	if len(result.AuthPolicies) > 0 {
		writeAuthPolicies(p, result.AuthPolicies)
	}

	if len(result.RouteCoverage) > 0 {
		writeRouteCoverage(p, result.RouteCoverage)
	}

	if len(result.Contradictions) > 0 {
		writeContradictions(p, result.Contradictions)
	}

	return p.err
}

type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(format string, args ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", args...)
}

func (p *printer) blank() {
	p.line("")
}

func (p *printer) raw(s string) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprint(p.w, s)
}

func writeAuthFlows(p *printer, flows []types.AuthFlow) {
	p.line("## Authentication Flows")
	p.blank()

	for _, flow := range flows {
		p.line("### Path: %s", flow.Name)
		p.line("Entry: %s:%s (line %d)", flow.Entry.File, flow.Entry.Function, flow.Entry.Line)

		if flow.Authentication != nil {
			a := flow.Authentication
			p.line("Authentication: %s:%s (line %d)", a.Location.File, a.Location.Function, a.Location.Line)
			for _, cfg := range a.Config {
				p.line("  - %s: %s", cfg.Name, formatConfigValue(cfg))
			}
		} else {
			p.line("Authentication: NONE")
		}

		for _, s := range flow.Sessions {
			p.line("Session: %s:%s (line %d)", s.File, s.Function, s.Line)
		}

		if flow.Authorization != nil {
			a := flow.Authorization
			p.line("Authorization: %s:%s (line %d)", a.Location.File, a.Location.Function, a.Location.Line)
			for _, cfg := range a.Config {
				p.line("  - %s: %s", cfg.Name, formatConfigValue(cfg))
			}
		} else {
			p.line("Authorization: NONE")
		}

		for _, v := range flow.Validators {
			p.line("Validator (%s): %s:%s (line %d)", v.Kind, v.Location.File, v.Location.Function, v.Location.Line)
			for _, cfg := range v.Config {
				p.line("  - %s: %s", cfg.Name, formatConfigValue(cfg))
			}
		}

		p.line("Combined posture: %s", flow.Posture)
		p.blank()
	}
}

func writeDefaults(p *printer, defaults []types.DefaultValue) {
	p.line("## Configuration Defaults")
	p.blank()
	p.line("| Field | Library Default | Operator Default | Platform Meaning |")
	p.line("|-------|----------------|-----------------|------------------|")

	for _, d := range defaults {
		lib := d.LibraryDefault
		if lib == "" {
			lib = "(not set)"
		}
		op := d.OperatorDefault
		if op == "" {
			op = "(not set)"
		}
		meaning := d.PlatformMeaning
		if meaning == "" {
			meaning = "(unknown)"
		}
		p.line("| %s | %s | %s | %s |", escapePipe(d.Field), escapePipe(lib), escapePipe(op), escapePipe(meaning))
	}
	p.blank()
}

func writeContracts(p *printer, contracts []types.Contract) {
	p.line("## Contract Violations")
	p.blank()

	for _, c := range contracts {
		if len(c.Violations) == 0 {
			continue
		}
		p.line("### %s:%s (line %d)", c.Function.File, c.Function.Function, c.Function.Line)
		p.line("Returns: %s", formatReturns(c.Returns))
		p.blank()

		for _, v := range c.Violations {
			p.line("- **%s**: %s at %s:%s (line %d)", v.Kind, v.Description, v.Caller.File, v.Caller.Function, v.Caller.Line)
		}
		p.blank()
	}
}

func writeErrorPaths(p *printer, paths []types.ErrorPath) {
	droppedCount := 0
	for _, ep := range paths {
		if ep.Dropped {
			droppedCount++
		}
	}

	p.line("## Error Propagation")
	p.blank()
	p.line("Total error creation points: %d", len(paths))
	p.line("Dropped errors: %d", droppedCount)
	p.blank()

	for _, ep := range paths {
		p.line("### %s:%s (line %d)", ep.Origin.File, ep.Origin.Function, ep.Origin.Line)
		p.line("Status: %s", errorStatus(ep))
		p.line("Fail mode: %s", ep.FailMode)

		if len(ep.Handlers) > 0 {
			p.line("Handlers:")
			for _, h := range ep.Handlers {
				p.line("  - %s at %s:%s (line %d)", h.Kind, h.Location.File, h.Location.Function, h.Location.Line)
			}
		}
		p.blank()
	}
}

func writeLifecycles(p *printer, lifecycles []types.ResourceLifecycle) {
	p.line("## Resource Lifecycles")
	p.blank()

	for _, lc := range lifecycles {
		p.line("### %s", lc.Resource)
		if lc.Create != nil {
			p.line("Create: %s:%s (line %d)", lc.Create.File, lc.Create.Function, lc.Create.Line)
		} else {
			p.line("Create: NONE")
		}

		if lc.Delete != nil {
			p.line("Delete: %s:%s (line %d)", lc.Delete.File, lc.Delete.Function, lc.Delete.Line)
		} else {
			p.line("Delete: NONE")
		}

		if lc.Owner != nil {
			p.line("Owner: %s:%s (line %d)", lc.Owner.File, lc.Owner.Function, lc.Owner.Line)
		} else {
			p.line("Owner: NONE")
		}

		if lc.Finalizer != nil {
			p.line("Finalizer: %s:%s (line %d)", lc.Finalizer.File, lc.Finalizer.Function, lc.Finalizer.Line)
		} else {
			p.line("Finalizer: NONE")
		}

		if lc.Orphanable {
			p.line("Risk: ORPHANABLE (no owner reference or finalizer)")
		}
		p.blank()
	}
}

func writeSecretExposures(p *printer, exposures []types.SecretExposure) {
	p.line("## Secret Exposures")
	p.blank()

	for _, se := range exposures {
		p.line("### %s at %s (line %d)", se.Pattern, se.Location.File, se.Location.Line)
		p.line("Field: %s", se.Field)
		p.line("Description: %s", se.Description)
		p.blank()
	}
}

func writeContradictions(p *printer, contradictions []types.Contradiction) {
	p.line("## Assumption Contradictions")
	p.blank()

	for _, c := range contradictions {
		p.line("### %s: %s", c.ID, c.Title)

		for _, a := range c.Assumptions {
			p.line("- %s:%s (line %d) ASSUMES: %s", a.Location.File, a.Location.Function, a.Location.Line, a.Description)
		}

		p.line("- Combined: %s", c.Reality)
		p.line("- Severity: %s", c.Severity)

		if c.Mitigation != "" {
			p.line("- Mitigation: %s", c.Mitigation)
		}
		p.blank()
	}
}

func writeAuthPolicies(p *printer, policies []types.AuthPolicyInfo) {
	p.line("## Auth Policies")
	p.blank()

	for _, pol := range policies {
		p.line("### %s (%s)", pol.Name, pol.Kind)
		p.line("File: %s", pol.File)
		if pol.TargetRef != "" {
			p.line("Target: %s", pol.TargetRef)
		}

		if len(pol.Rules) > 0 {
			p.line("Rules:")
			for _, r := range pol.Rules {
				if r.Priority > 0 {
					p.line("  - [%s] %s (priority %d)", r.Kind, r.Name, r.Priority)
				} else {
					p.line("  - [%s] %s", r.Kind, r.Name)
				}
			}
		}

		if len(pol.SkipPaths) > 0 {
			p.line("Skip paths: %s", strings.Join(pol.SkipPaths, ", "))
		}
		p.blank()
	}
}

func writeRouteCoverage(p *printer, coverage []types.RouteCoverage) {
	p.line("## Route Coverage")
	p.blank()
	p.line("| Route | Kind | Backend | Policy | Covered | Mechanism |")
	p.line("|-------|------|---------|--------|---------|-----------|")

	for _, c := range coverage {
		covered := "NO"
		if c.Covered {
			covered = "YES"
		}
		mechanism := c.Mechanism
		if mechanism == "" {
			mechanism = "-"
		}
		p.line("| %s | %s | %s | %s | %s | %s |",
			escapePipe(c.Route),
			escapePipe(c.RouteKind),
			escapePipe(c.Backend),
			escapePipe(c.Policy),
			covered,
			escapePipe(mechanism),
		)
	}
	p.blank()
}

func formatConfigValue(cfg types.ConfigField) string {
	parts := []string{cfg.Value}
	if cfg.PlatformMeaning != "" {
		parts = append(parts, "("+cfg.PlatformMeaning+")")
	}
	return strings.Join(parts, " ")
}

func formatReturns(returns []types.ReturnInfo) string {
	var parts []string
	for _, r := range returns {
		desc := r.Type
		if r.IsError {
			desc += " (error)"
		}
		if r.CanBeNil {
			desc += " (nillable)"
		}
		parts = append(parts, desc)
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

// escapePipe escapes pipe characters in markdown table cell content.
func escapePipe(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func errorStatus(ep types.ErrorPath) string {
	if ep.Dropped {
		return "DROPPED"
	}
	return "HANDLED"
}
