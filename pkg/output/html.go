package output

import (
	"fmt"
	"html/template"
	"io"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// WriteHTML writes the analysis result as a self-contained HTML report.
func WriteHTML(w io.Writer, result *types.AnalysisResult) error {
	tmpl, err := template.New("report").Funcs(htmlFuncMap()).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("parsing HTML template: %w", err)
	}
	return tmpl.Execute(w, result)
}

func htmlFuncMap() template.FuncMap {
	return template.FuncMap{
		"severityClass": func(s string) string {
			switch strings.ToUpper(s) {
			case "HIGH", "PERMISSIVE":
				return "severity-high"
			case "MEDIUM":
				return "severity-medium"
			case "LOW", "RESTRICTIVE":
				return "severity-low"
			case "NEUTRAL":
				return "severity-unknown"
			default:
				return "severity-unknown"
			}
		},
		"coverageClass": func(covered bool, mechanism string) string {
			if strings.ToUpper(mechanism) == "INTENTIONAL" {
				return "coverage-intentional"
			}
			if covered {
				return "coverage-yes"
			}
			return "coverage-no"
		},
		"coverageLabel": func(covered bool, mechanism string) string {
			if strings.ToUpper(mechanism) == "INTENTIONAL" {
				return "INTENTIONAL"
			}
			if covered {
				return "YES"
			}
			return "NO"
		},
		"errorStatus": func(ep types.ErrorPath) string {
			if ep.Dropped {
				return "DROPPED"
			}
			return "HANDLED"
		},
		"errorStatusClass": func(ep types.ErrorPath) string {
			if ep.Dropped {
				return "severity-high"
			}
			return "severity-low"
		},
		"droppedCount": func(paths []types.ErrorPath) int {
			n := 0
			for _, ep := range paths {
				if ep.Dropped {
					n++
				}
			}
			return n
		},
		"violationCount": func(contracts []types.Contract) int {
			n := 0
			for _, c := range contracts {
				n += len(c.Violations)
			}
			return n
		},
		"configValue": func(cfg types.ConfigField) string {
			parts := []string{cfg.Value}
			if cfg.PlatformMeaning != "" {
				parts = append(parts, "("+cfg.PlatformMeaning+")")
			}
			return strings.Join(parts, " ")
		},
		"join": strings.Join,
		"upper": strings.ToUpper,
		"sub": func(a, b int) int {
			return a - b
		},
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Trust Flow Map: {{.Project}}</title>
<style>
:root {
  --bg: #ffffff;
  --bg-secondary: #f8f9fa;
  --bg-card: #ffffff;
  --text: #212529;
  --text-secondary: #6c757d;
  --border: #dee2e6;
  --header-bg: #1a1a2e;
  --header-text: #e0e0e0;
  --accent: #4361ee;
  --accent-hover: #3a56d4;
  --code-bg: #f1f3f5;
  --shadow: rgba(0,0,0,0.08);
  --high: #dc3545;
  --medium: #fd7e14;
  --low: #ffc107;
  --yes: #28a745;
  --no: #dc3545;
  --intentional: #6c757d;
}

[data-theme="dark"] {
  --bg: #1a1a2e;
  --bg-secondary: #16213e;
  --bg-card: #1f2937;
  --text: #e0e0e0;
  --text-secondary: #9ca3af;
  --border: #374151;
  --header-bg: #0f0f23;
  --header-text: #e0e0e0;
  --accent: #6c8cff;
  --accent-hover: #8fa8ff;
  --code-bg: #111827;
  --shadow: rgba(0,0,0,0.3);
  --high: #ef4444;
  --medium: #f97316;
  --low: #eab308;
  --yes: #22c55e;
  --no: #ef4444;
  --intentional: #9ca3af;
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.6;
  transition: background-color 0.3s, color 0.3s;
}

header {
  background: var(--header-bg);
  color: var(--header-text);
  padding: 1.5rem 2rem;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 2px 8px var(--shadow);
}

header h1 {
  font-size: 1.4rem;
  font-weight: 600;
  margin-bottom: 1rem;
}

.controls {
  display: flex;
  gap: 0.75rem;
  align-items: center;
  flex-wrap: wrap;
}

#search {
  flex: 1;
  min-width: 200px;
  max-width: 400px;
  padding: 0.5rem 0.75rem;
  border: 1px solid rgba(255,255,255,0.2);
  border-radius: 6px;
  background: rgba(255,255,255,0.1);
  color: var(--header-text);
  font-size: 0.875rem;
}

#search::placeholder { color: rgba(255,255,255,0.5); }
#search:focus { outline: none; border-color: var(--accent); }

.btn {
  padding: 0.5rem 1rem;
  border: 1px solid rgba(255,255,255,0.2);
  border-radius: 6px;
  background: rgba(255,255,255,0.1);
  color: var(--header-text);
  cursor: pointer;
  font-size: 0.875rem;
  transition: background 0.2s;
}

.btn:hover { background: rgba(255,255,255,0.2); }

.summary-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
  gap: 0.75rem;
  margin-top: 1rem;
}

.summary-box {
  background: rgba(255,255,255,0.08);
  border-radius: 8px;
  padding: 0.6rem 0.8rem;
  text-align: center;
}

.summary-box .count {
  font-size: 1.5rem;
  font-weight: 700;
  display: block;
}

.summary-box .label {
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  opacity: 0.8;
}

main {
  max-width: 1200px;
  margin: 0 auto;
  padding: 1.5rem;
}

.section {
  margin-bottom: 1rem;
  border: 1px solid var(--border);
  border-radius: 8px;
  overflow: hidden;
  background: var(--bg-card);
  box-shadow: 0 1px 3px var(--shadow);
}

.section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.75rem 1rem;
  background: var(--bg-secondary);
  cursor: pointer;
  user-select: none;
  border-bottom: 1px solid var(--border);
  transition: background 0.2s;
}

.section-header:hover { opacity: 0.9; }

.section-header h2 {
  font-size: 1rem;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.section-header .badge {
  display: inline-block;
  padding: 0.15rem 0.5rem;
  border-radius: 10px;
  font-size: 0.75rem;
  font-weight: 600;
  background: var(--accent);
  color: #fff;
}

.section-header .chevron {
  transition: transform 0.2s;
  font-size: 0.875rem;
}

.section.collapsed .section-header .chevron {
  transform: rotate(-90deg);
}

.section-body {
  padding: 1rem;
  overflow-x: auto;
}

.section.collapsed .section-body {
  display: none;
}

.card {
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 0.75rem 1rem;
  margin-bottom: 0.75rem;
  background: var(--bg);
  transition: box-shadow 0.2s;
}

.card:last-child { margin-bottom: 0; }
.card:hover { box-shadow: 0 2px 6px var(--shadow); }

.card h3 {
  font-size: 0.875rem;
  font-weight: 600;
  margin-bottom: 0.4rem;
  word-break: break-all;
}

.card-detail {
  font-size: 0.8rem;
  color: var(--text-secondary);
  margin-bottom: 0.2rem;
}

.card-detail code {
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.8rem;
  background: var(--code-bg);
  padding: 0.1rem 0.3rem;
  border-radius: 3px;
}

.severity-badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  color: #fff;
}

.severity-high { background: var(--high); }
.severity-medium { background: var(--medium); }
.severity-low { background: var(--low); color: #212529; }
.severity-unknown { background: var(--intentional); }

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.8rem;
}

th {
  background: var(--bg-secondary);
  text-align: left;
  padding: 0.5rem 0.75rem;
  font-weight: 600;
  border-bottom: 2px solid var(--border);
  white-space: nowrap;
}

td {
  padding: 0.4rem 0.75rem;
  border-bottom: 1px solid var(--border);
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.75rem;
  word-break: break-all;
}

tr:hover td { background: var(--bg-secondary); }

.coverage-yes { color: var(--yes); font-weight: 700; }
.coverage-no { color: var(--no); font-weight: 700; }
.coverage-intentional { color: var(--intentional); font-weight: 700; }

.posture-badge {
  display: inline-block;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
}

.posture-permissive { background: var(--high); color: #fff; }
.posture-restrictive { background: var(--yes); color: #fff; }
.posture-unknown { background: var(--intentional); color: #fff; }

.auth-path {
  font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
  font-size: 0.75rem;
  background: var(--code-bg);
  padding: 0.5rem;
  border-radius: 4px;
  margin: 0.4rem 0;
  white-space: pre-wrap;
  word-break: break-all;
}

.flow-step {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  margin-bottom: 0.3rem;
}

.flow-step .step-marker {
  flex-shrink: 0;
  width: 1.2rem;
  text-align: center;
  font-weight: 700;
  color: var(--accent);
}

.flow-step .step-content {
  flex: 1;
  font-size: 0.8rem;
}

.no-results {
  text-align: center;
  padding: 2rem;
  color: var(--text-secondary);
  font-style: italic;
}

.hidden { display: none !important; }

@media (max-width: 768px) {
  header { padding: 1rem; }
  main { padding: 1rem; }
  .summary-grid { grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); }
}
</style>
</head>
<body>

<header>
  <h1>Trust Flow Map: {{.Project}}</h1>
  <div class="controls">
    <input type="text" id="search" placeholder="Filter findings..." autocomplete="off">
    <button class="btn" id="theme-toggle">Dark Mode</button>
    <button class="btn" id="expand-all">Expand All</button>
    <button class="btn" id="collapse-all">Collapse All</button>
  </div>
  <div class="summary-grid">
    <div class="summary-box"><span class="count">{{len .AuthFlows}}</span><span class="label">Auth Flows</span></div>
    <div class="summary-box"><span class="count">{{len .Defaults}}</span><span class="label">Defaults</span></div>
    <div class="summary-box"><span class="count">{{len .Contracts}}</span><span class="label">Contracts</span></div>
    <div class="summary-box"><span class="count">{{len .ErrorPaths}}</span><span class="label">Error Paths</span></div>
    <div class="summary-box"><span class="count">{{len .Lifecycles}}</span><span class="label">Lifecycles</span></div>
    <div class="summary-box"><span class="count">{{len .SecretExposures}}</span><span class="label">Secrets</span></div>
    <div class="summary-box"><span class="count">{{len .AuthPolicies}}</span><span class="label">Auth Policies</span></div>
    <div class="summary-box"><span class="count">{{len .RouteCoverage}}</span><span class="label">Routes</span></div>
    <div class="summary-box"><span class="count">{{len .NetworkPolicies}}</span><span class="label">Net Policies</span></div>
    <div class="summary-box"><span class="count">{{len .RBACFindings}}</span><span class="label">RBAC</span></div>
    <div class="summary-box"><span class="count">{{len .MeshPolicies}}</span><span class="label">Mesh Policies</span></div>
    <div class="summary-box"><span class="count">{{len .TemplateRisks}}</span><span class="label">Template Risks</span></div>
    <div class="summary-box"><span class="count">{{len .WebhookDefaults}}</span><span class="label">Webhooks</span></div>
    <div class="summary-box"><span class="count">{{len .WebhookValidations}}</span><span class="label">Validators</span></div>
    <div class="summary-box"><span class="count">{{len .PostureChecks}}</span><span class="label">Posture</span></div>
    <div class="summary-box"><span class="count">{{len .Contradictions}}</span><span class="label">Contradictions</span></div>
  </div>
</header>

<main>

{{if .AuthFlows}}
<div class="section collapsed" data-section="auth-flows">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Authentication Flows <span class="badge">{{len .AuthFlows}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .AuthFlows}}
    <div class="card" data-searchable>
      <h3>{{.Name}}</h3>
      <div class="card-detail">Entry: <code>{{.Entry.File}}:{{.Entry.Function}} (line {{.Entry.Line}})</code></div>
      {{if .Authentication}}
      <div class="flow-step"><span class="step-marker">1</span><span class="step-content">Authentication: <code>{{.Authentication.Location.File}}:{{.Authentication.Location.Function}} (line {{.Authentication.Location.Line}})</code>{{range .Authentication.Config}}<br>&nbsp;&nbsp;{{.Name}}: {{configValue .}}{{end}}</span></div>
      {{else}}
      <div class="flow-step"><span class="step-marker">1</span><span class="step-content">Authentication: <span class="severity-badge severity-high">NONE</span></span></div>
      {{end}}
      {{range $i, $s := .Sessions}}
      <div class="flow-step"><span class="step-marker">&#8226;</span><span class="step-content">Session: <code>{{$s.File}}:{{$s.Function}} (line {{$s.Line}})</code></span></div>
      {{end}}
      {{if .Authorization}}
      <div class="flow-step"><span class="step-marker">2</span><span class="step-content">Authorization: <code>{{.Authorization.Location.File}}:{{.Authorization.Location.Function}} (line {{.Authorization.Location.Line}})</code>{{range .Authorization.Config}}<br>&nbsp;&nbsp;{{.Name}}: {{configValue .}}{{end}}</span></div>
      {{else}}
      <div class="flow-step"><span class="step-marker">2</span><span class="step-content">Authorization: <span class="severity-badge severity-high">NONE</span></span></div>
      {{end}}
      {{range .Validators}}
      <div class="flow-step"><span class="step-marker">&#10003;</span><span class="step-content">Validator ({{.Kind}}): <code>{{.Location.File}}:{{.Location.Function}} (line {{.Location.Line}})</code>{{range .Config}}<br>&nbsp;&nbsp;{{.Name}}: {{configValue .}}{{end}}</span></div>
      {{end}}
      <div class="card-detail">Posture: <span class="posture-badge posture-{{if eq .Posture "PERMISSIVE"}}permissive{{else if eq .Posture "RESTRICTIVE"}}restrictive{{else}}unknown{{end}}">{{.Posture}}</span></div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .Defaults}}
<div class="section collapsed" data-section="defaults">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Configuration Defaults <span class="badge">{{len .Defaults}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    <table>
      <thead>
        <tr><th>Field</th><th>Library Default</th><th>Operator Default</th><th>Platform Meaning</th><th>Permissiveness</th></tr>
      </thead>
      <tbody>
        {{range .Defaults}}
        <tr data-searchable>
          <td>{{.Field}}</td>
          <td>{{if .LibraryDefault}}{{.LibraryDefault}}{{else}}(not set){{end}}</td>
          <td>{{if .OperatorDefault}}{{.OperatorDefault}}{{else}}(not set){{end}}</td>
          <td>{{if .PlatformMeaning}}{{.PlatformMeaning}}{{else}}(unknown){{end}}</td>
          <td>{{if .Permissiveness}}<span class="severity-badge {{severityClass .Permissiveness}}">{{.Permissiveness}}</span>{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</div>
{{end}}

{{if .Contracts}}
<div class="section collapsed" data-section="contracts">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Contract Violations <span class="badge">{{violationCount .Contracts}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .Contracts}}
    {{if .Violations}}
    <div class="card" data-searchable>
      <h3><code>{{.Function.File}}:{{.Function.Function}} (line {{.Function.Line}})</code></h3>
      {{range .Violations}}
      <div class="card-detail"><span class="severity-badge severity-medium">{{.Kind}}</span> {{.Description}} at <code>{{.Caller.File}}:{{.Caller.Function}} (line {{.Caller.Line}})</code></div>
      {{end}}
    </div>
    {{end}}
    {{end}}
  </div>
</div>
{{end}}

{{if .ErrorPaths}}
<div class="section collapsed" data-section="error-paths">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Error Propagation <span class="badge">{{len .ErrorPaths}}</span> <span class="badge severity-high" style="margin-left:0.3rem">{{droppedCount .ErrorPaths}} dropped</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .ErrorPaths}}
    <div class="card" data-searchable>
      <h3><code>{{.Origin.File}}:{{.Origin.Function}} (line {{.Origin.Line}})</code></h3>
      <div class="card-detail">Status: <span class="severity-badge {{errorStatusClass .}}">{{errorStatus .}}</span></div>
      <div class="card-detail">Fail mode: {{.FailMode}}</div>
      {{if .Handlers}}
      <div class="card-detail">Handlers:</div>
      {{range .Handlers}}
      <div class="card-detail">&nbsp;&nbsp;{{.Kind}} at <code>{{.Location.File}}:{{.Location.Function}} (line {{.Location.Line}})</code></div>
      {{end}}
      {{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .Lifecycles}}
<div class="section collapsed" data-section="lifecycles">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Resource Lifecycles <span class="badge">{{len .Lifecycles}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .Lifecycles}}
    <div class="card" data-searchable>
      <h3>{{.Resource}}</h3>
      <div class="card-detail">Create: {{if .Create}}<code>{{.Create.File}}:{{.Create.Function}} (line {{.Create.Line}})</code>{{else}}NONE{{end}}</div>
      <div class="card-detail">Delete: {{if .Delete}}<code>{{.Delete.File}}:{{.Delete.Function}} (line {{.Delete.Line}})</code>{{else}}NONE{{end}}</div>
      <div class="card-detail">Owner: {{if .Owner}}<code>{{.Owner.File}}:{{.Owner.Function}} (line {{.Owner.Line}})</code>{{else}}NONE{{end}}</div>
      <div class="card-detail">Finalizer: {{if .Finalizer}}<code>{{.Finalizer.File}}:{{.Finalizer.Function}} (line {{.Finalizer.Line}})</code>{{else}}NONE{{end}}</div>
      {{if .Orphanable}}<div class="card-detail"><span class="severity-badge severity-high">ORPHANABLE</span> no owner reference or finalizer</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .SecretExposures}}
<div class="section collapsed" data-section="secrets">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Secret Exposures <span class="badge">{{len .SecretExposures}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .SecretExposures}}
    <div class="card" data-searchable>
      <h3>{{.Pattern}} at <code>{{.Location.File}} (line {{.Location.Line}})</code></h3>
      <div class="card-detail">Field: {{.Field}}</div>
      <div class="card-detail">{{.Description}}</div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .AuthPolicies}}
<div class="section collapsed" data-section="auth-policies">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Auth Policies <span class="badge">{{len .AuthPolicies}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .AuthPolicies}}
    <div class="card" data-searchable>
      <h3>{{.Name}} ({{.Kind}})</h3>
      <div class="card-detail">File: <code>{{.File}}</code></div>
      {{if .TargetRef}}<div class="card-detail">Target: {{.TargetRef}}</div>{{end}}
      {{if .Rules}}
      <div class="card-detail">Rules:</div>
      {{range .Rules}}
      <div class="card-detail">&nbsp;&nbsp;[{{.Kind}}] {{.Name}}{{if gt .Priority 0}} (priority {{.Priority}}){{end}}</div>
      {{end}}
      {{end}}
      {{if .SkipPaths}}<div class="card-detail">Skip paths: {{join .SkipPaths ", "}}</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .RouteCoverage}}
<div class="section collapsed" data-section="route-coverage">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Route Coverage <span class="badge">{{len .RouteCoverage}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    <table>
      <thead>
        <tr><th>Route</th><th>Kind</th><th>Backend</th><th>Policy</th><th>Covered</th><th>Mechanism</th></tr>
      </thead>
      <tbody>
        {{range .RouteCoverage}}
        <tr data-searchable>
          <td>{{.Route}}</td>
          <td>{{.RouteKind}}</td>
          <td>{{.Backend}}</td>
          <td>{{.Policy}}</td>
          <td><span class="{{coverageClass .Covered .Mechanism}}">{{coverageLabel .Covered .Mechanism}}</span></td>
          <td>{{if .Mechanism}}{{.Mechanism}}{{else}}-{{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</div>
{{end}}

{{if .NetworkPolicies}}
<div class="section collapsed" data-section="network-policies">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Network Policies <span class="badge">{{len .NetworkPolicies}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .NetworkPolicies}}
    <div class="card" data-searchable>
      <h3>{{.Name}}</h3>
      <div class="card-detail">File: <code>{{.File}}</code></div>
      {{if .Namespace}}<div class="card-detail">Namespace: {{.Namespace}}</div>{{end}}
      <div class="card-detail">Pod selector: {{.PodSelector}}</div>
      {{if .PolicyTypes}}<div class="card-detail">Policy types: {{join .PolicyTypes ", "}}</div>{{end}}
      {{if .IngressFrom}}
      <div class="card-detail">Ingress from:</div>
      {{range .IngressFrom}}<div class="card-detail">&nbsp;&nbsp;{{.}}</div>{{end}}
      {{end}}
      {{if .EgressTo}}
      <div class="card-detail">Egress to:</div>
      {{range .EgressTo}}<div class="card-detail">&nbsp;&nbsp;{{.}}</div>{{end}}
      {{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .RBACFindings}}
<div class="section collapsed" data-section="rbac">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>RBAC Findings <span class="badge">{{len .RBACFindings}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .RBACFindings}}
    <div class="card" data-searchable>
      <h3>{{.Name}} ({{.Kind}})</h3>
      <div class="card-detail">File: <code>{{.File}}</code></div>
      <div class="card-detail">Severity: <span class="severity-badge {{severityClass .Severity}}">{{.Severity}}</span></div>
      <div class="card-detail">Rule: {{.Rule}}</div>
      <div class="card-detail">Reason: {{.Reason}}</div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .MeshPolicies}}
<div class="section collapsed" data-section="mesh-policies">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Service Mesh Policies <span class="badge">{{len .MeshPolicies}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .MeshPolicies}}
    <div class="card" data-searchable>
      <h3>{{.Name}} ({{.Kind}})</h3>
      <div class="card-detail">File: <code>{{.File}}</code></div>
      {{if .Namespace}}<div class="card-detail">Namespace: {{.Namespace}}</div>{{end}}
      <div class="card-detail">mTLS mode: {{.MTLSMode}}</div>
      <div class="card-detail">Scope: {{.Scope}}</div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .TemplateRisks}}
<div class="section collapsed" data-section="template-risks">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Template Risks <span class="badge">{{len .TemplateRisks}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .TemplateRisks}}
    <div class="card" data-searchable>
      <h3>{{.Kind}} at <code>{{.File}} (line {{.Line}})</code></h3>
      <div class="card-detail">Field: {{.Field}}</div>
      <div class="card-detail">Severity: <span class="severity-badge {{severityClass .Severity}}">{{.Severity}}</span></div>
      <div class="card-detail">{{.Description}}</div>
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .WebhookDefaults}}
<div class="section collapsed" data-section="webhooks">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Webhook Defaults <span class="badge">{{len .WebhookDefaults}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .WebhookDefaults}}
    <div class="card" data-searchable>
      <h3>{{.Function}} (<code>{{.File}}</code> line {{.Line}})</h3>
      {{if .FieldsSet}}<div class="card-detail">Sets: {{join .FieldsSet ", "}}</div>{{end}}
      {{if .FieldsUnset}}<div class="card-detail">Does NOT set: {{join .FieldsUnset ", "}}</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .WebhookValidations}}
<div class="section collapsed" data-section="webhook-validations">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Webhook Validations <span class="badge">{{len .WebhookValidations}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .WebhookValidations}}
    <div class="card" data-searchable>
      <h3>{{.Function}} (<code>{{.File}}</code> line {{.Line}})</h3>
      {{if .FieldsChecked}}<div class="card-detail">Checks: {{join .FieldsChecked ", "}}</div>{{end}}
      {{if .FieldsUnchecked}}<div class="card-detail">Does NOT check: {{join .FieldsUnchecked ", "}}</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

{{if .PostureChecks}}
<div class="section" data-section="posture">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Security Posture <span class="badge">{{len .PostureChecks}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    <table>
      <thead>
        <tr><th>Check</th><th>Category</th><th>Status</th><th>Details</th></tr>
      </thead>
      <tbody>
        {{range .PostureChecks}}
        <tr data-searchable>
          <td style="font-family: inherit;">{{.Name}}</td>
          <td style="font-family: inherit;">{{.Category}}</td>
          <td><span class="severity-badge {{if eq .Status "PASS"}}severity-low{{else if eq .Status "FAIL"}}severity-high{{else if eq .Status "PARTIAL"}}severity-medium{{else}}severity-unknown{{end}}" style="{{if eq .Status "PASS"}}background: var(--yes); color: #fff;{{end}}">{{.Status}}</span></td>
          <td style="font-family: inherit;">{{.Details}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>
</div>
{{end}}

{{if .Contradictions}}
<div class="section" data-section="contradictions">
  <div class="section-header" onclick="toggleSection(this)">
    <h2>Assumption Contradictions <span class="badge severity-high">{{len .Contradictions}}</span></h2>
    <span class="chevron">&#9660;</span>
  </div>
  <div class="section-body">
    {{range .Contradictions}}
    <div class="card" data-searchable>
      <h3>{{.ID}}: {{.Title}} <span class="severity-badge {{severityClass .Severity}}">{{.Severity}}</span></h3>
      {{range .Assumptions}}
      <div class="card-detail"><code>{{.Location.File}}:{{.Location.Function}} (line {{.Location.Line}})</code> ASSUMES: {{.Description}}</div>
      {{end}}
      <div class="card-detail"><strong>Combined:</strong> {{.Reality}}</div>
      {{if .Mitigation}}<div class="card-detail"><strong>Mitigation:</strong> {{.Mitigation}}</div>{{end}}
    </div>
    {{end}}
  </div>
</div>
{{end}}

</main>

<script>
(function() {
  'use strict';

  // Theme toggle
  var themeBtn = document.getElementById('theme-toggle');
  var html = document.documentElement;
  var savedTheme = localStorage.getItem('tfa-theme') || 'light';
  html.setAttribute('data-theme', savedTheme);
  updateThemeBtn();

  themeBtn.addEventListener('click', function() {
    var current = html.getAttribute('data-theme');
    var next = current === 'light' ? 'dark' : 'light';
    html.setAttribute('data-theme', next);
    localStorage.setItem('tfa-theme', next);
    updateThemeBtn();
  });

  function updateThemeBtn() {
    themeBtn.textContent = html.getAttribute('data-theme') === 'light' ? 'Dark Mode' : 'Light Mode';
  }

  // Collapsible sections
  window.toggleSection = function(header) {
    var section = header.parentElement;
    section.classList.toggle('collapsed');
  };

  // Expand/collapse all
  document.getElementById('expand-all').addEventListener('click', function() {
    var sections = document.querySelectorAll('.section');
    for (var i = 0; i < sections.length; i++) {
      sections[i].classList.remove('collapsed');
    }
  });

  document.getElementById('collapse-all').addEventListener('click', function() {
    var sections = document.querySelectorAll('.section');
    for (var i = 0; i < sections.length; i++) {
      sections[i].classList.add('collapsed');
    }
  });

  // Search/filter
  var searchInput = document.getElementById('search');
  searchInput.addEventListener('input', function() {
    var query = this.value.toLowerCase().trim();
    var items = document.querySelectorAll('[data-searchable]');
    var sections = document.querySelectorAll('.section');

    if (!query) {
      for (var i = 0; i < items.length; i++) {
        items[i].classList.remove('hidden');
      }
      for (var j = 0; j < sections.length; j++) {
        sections[j].classList.remove('hidden');
      }
      return;
    }

    // First pass: show/hide individual items
    for (var k = 0; k < items.length; k++) {
      var text = items[k].textContent.toLowerCase();
      if (text.indexOf(query) !== -1) {
        items[k].classList.remove('hidden');
      } else {
        items[k].classList.add('hidden');
      }
    }

    // Second pass: hide sections with no visible items, expand sections with matches
    for (var m = 0; m < sections.length; m++) {
      var visibleItems = sections[m].querySelectorAll('[data-searchable]:not(.hidden)');
      if (visibleItems.length === 0) {
        sections[m].classList.add('hidden');
      } else {
        sections[m].classList.remove('hidden');
        sections[m].classList.remove('collapsed');
      }
    }
  });
})();
</script>

</body>
</html>`
