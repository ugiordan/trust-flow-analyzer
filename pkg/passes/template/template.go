package template

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// skipDirs mirrors the loader's skip set so the walk stays consistent.
var skipDirs = map[string]bool{
	".git":         true,
	"__pycache__":  true,
	"node_modules": true,
	"venv":         true,
	".venv":        true,
	"target":       true,
	"vendor":       true,
	".tox":         true,
	"dist":         true,
	"build":        true,
	"public":       true,
	"static":       true,
	".next":        true,
	"coverage":     true,
}

// templateExts lists file extensions that are always scanned as template files.
var templateExts = map[string]bool{
	".tmpl": true,
	".tpl":  true,
}

// secretVarPattern matches shell-style $(VAR) references where VAR contains
// secret-related substrings. Same pattern as the secrets pass for consistency.
var secretVarPattern = regexp.MustCompile(`\$\((?:[A-Z_]*?)(?:PASSWORD|SECRET|TOKEN|KEY)(?:[A-Z_]*?)\)`)

// conditionalSecurityPattern matches Go template conditionals that gate security
// components (e.g. {{ if .Spec.KubeRBACProxy }}, {{- if .Spec.TLS }}).
var conditionalSecurityPattern = regexp.MustCompile(`\{\{-?\s*if\s+\.(?:[A-Za-z]+\.)*([A-Za-z]+)\s*\}\}`)

// securityComponentNames lists field names that indicate a security component.
var securityComponentNames = map[string]bool{
	"KubeRBACProxy": true,
	"OAuthProxy":    true,
	"TLS":           true,
	"Auth":          true,
	"Authorino":     true,
	"MTLS":          true,
	"mTLS":          true,
}

// hardcodedSecretPattern matches literal values assigned to password/secret fields
// in YAML. It catches patterns like "password: mypass123" but NOT template vars.
var hardcodedSecretPattern = regexp.MustCompile(`(?i)^\s*(?:password|secret|secret_key|api_key|token):\s*["']?([^"'\s{][^"'\s]*)["']?\s*$`)

// base64SecretPattern matches base64-encoded data in Secret manifests.
var base64SecretPattern = regexp.MustCompile(`^\s*[A-Za-z0-9_.-]+:\s*[A-Za-z0-9+/]{16,}={0,2}\s*$`)

// Pass implements the template risk analysis pass.
type Pass struct{}

func (p *Pass) Name() string { return "template" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.ArchContext != nil && len(ctx.ArchContext.SecurityAnnotations) > 0 {
		return p.runFromArchContext(ctx)
	}
	return p.runSelfExtract(ctx)
}

func (p *Pass) runFromArchContext(ctx *passes.Context) error {
	var risks []types.TemplateRisk

	for _, ann := range ctx.ArchContext.SecurityAnnotations {
		switch ann.Type {
		case "SECRET_IN_CONTAINER_ARGS":
			risks = append(risks, types.TemplateRisk{
				File:        "arch-context",
				Line:        0,
				Kind:        "SECRET_IN_ARGS",
				Field:       ann.Source,
				Severity:    ann.Severity,
				Description: ann.Description,
			})
		case "CRD_CONFUSED_DEPUTY":
			risks = append(risks, types.TemplateRisk{
				File:        "arch-context",
				Line:        0,
				Kind:        "CONDITIONAL_SECURITY",
				Field:       ann.Source,
				Severity:    ann.Severity,
				Description: ann.Description,
			})
		}
	}

	sort.Slice(risks, func(i, j int) bool {
		if risks[i].File != risks[j].File {
			return risks[i].File < risks[j].File
		}
		return risks[i].Line < risks[j].Line
	})

	ctx.Result.TemplateRisks = append(ctx.Result.TemplateRisks, risks...)
	return nil
}

func (p *Pass) runSelfExtract(ctx *passes.Context) error {
	rootDir := ctx.Program.RootDir

	var risks []types.TemplateRisk

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		if !shouldScan(path) {
			return nil
		}

		relPath := relativePath(rootDir, path)
		fileRisks := scanFile(path, relPath)
		risks = append(risks, fileRisks...)
		return nil
	})
	if err != nil {
		return err
	}

	sort.Slice(risks, func(i, j int) bool {
		if risks[i].File != risks[j].File {
			return risks[i].File < risks[j].File
		}
		return risks[i].Line < risks[j].Line
	})

	ctx.Result.TemplateRisks = append(ctx.Result.TemplateRisks, risks...)
	return nil
}

// shouldScan returns true if the file should be scanned for template risks.
// Template files (.tmpl, .yaml.tmpl, .tpl) are always scanned. Regular YAML
// files are scanned only if they contain Go template syntax.
func shouldScan(path string) bool {
	base := filepath.Base(path)

	// Check for compound extensions like .yaml.tmpl
	if strings.HasSuffix(base, ".yaml.tmpl") || strings.HasSuffix(base, ".yml.tmpl") {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	if templateExts[ext] {
		return true
	}

	if ext == ".yaml" || ext == ".yml" {
		return containsTemplateSyntax(path)
	}

	return false
}

// containsTemplateSyntax reads the first 8KB of a file to check for {{ syntax.
func containsTemplateSyntax(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	return strings.Contains(string(buf[:n]), "{{")
}

// scanFile scans a single file for template security risks.
func scanFile(path, relPath string) []types.TemplateRisk {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var risks []types.TemplateRisk

	scanner := bufio.NewScanner(f)
	lineNum := 0

	// State tracking for container spec context.
	inContainerSpec := false
	inArgsOrCommand := false
	containerIndent := 0
	argsIndent := 0

	// State tracking for Secret manifest context.
	inSecretKind := false

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Track whether we're in a Secret manifest.
		if strings.HasPrefix(trimmed, "kind:") {
			kindVal := strings.TrimSpace(strings.TrimPrefix(trimmed, "kind:"))
			inSecretKind = kindVal == "Secret"
		}

		// Track container spec context.
		if strings.HasPrefix(trimmed, "containers:") {
			inContainerSpec = true
			containerIndent = indent
			inArgsOrCommand = false
			continue
		}

		// Exit container spec when we reach a line at or before the container indent level
		// (but skip blank lines and comments).
		if inContainerSpec && trimmed != "" && !strings.HasPrefix(trimmed, "#") && indent <= containerIndent {
			if !strings.HasPrefix(trimmed, "-") {
				inContainerSpec = false
				inArgsOrCommand = false
			}
		}

		// Track args/command sections within container spec.
		if inContainerSpec {
			if strings.HasPrefix(trimmed, "args:") || strings.HasPrefix(trimmed, "command:") {
				inArgsOrCommand = true
				argsIndent = indent
				// Check inline content on same line.
				risks = append(risks, checkSecretInArgs(trimmed, relPath, lineNum)...)
				continue
			}

			// Exit args/command when indent drops back.
			if inArgsOrCommand && trimmed != "" && indent <= argsIndent && !strings.HasPrefix(trimmed, "-") {
				inArgsOrCommand = false
			}
		}

		// Check for secret vars in args/command lines.
		if inArgsOrCommand {
			risks = append(risks, checkSecretInArgs(line, relPath, lineNum)...)
		}

		// Check for conditional security components (works anywhere in the file).
		risks = append(risks, checkConditionalSecurity(line, relPath, lineNum)...)

		// Check for hardcoded credentials.
		risks = append(risks, checkHardcodedCredential(trimmed, relPath, lineNum)...)

		// Check for base64 secrets in Secret manifests.
		if inSecretKind {
			risks = append(risks, checkBase64Secret(trimmed, relPath, lineNum)...)
		}
	}

	return risks
}

// checkSecretInArgs looks for $(VAR) patterns with secret-related names in
// args/command fields.
func checkSecretInArgs(line, relPath string, lineNum int) []types.TemplateRisk {
	matches := secretVarPattern.FindAllString(line, -1)
	if len(matches) == 0 {
		return nil
	}

	var risks []types.TemplateRisk
	for _, match := range matches {
		risks = append(risks, types.TemplateRisk{
			File:     relPath,
			Line:     lineNum,
			Kind:     "SECRET_IN_ARGS",
			Field:    match,
			Severity: "HIGH",
			Description: "Environment variable " + match + " expanded in container args. " +
				"Kubelet expands env vars in args into /proc/1/cmdline, exposing the secret " +
				"to any process that can read /proc.",
		})
	}
	return risks
}

// checkConditionalSecurity looks for Go template conditionals that gate
// security components.
func checkConditionalSecurity(line, relPath string, lineNum int) []types.TemplateRisk {
	matches := conditionalSecurityPattern.FindAllStringSubmatch(line, -1)
	if len(matches) == 0 {
		return nil
	}

	var risks []types.TemplateRisk
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		fieldName := match[1]
		if !securityComponentNames[fieldName] {
			continue
		}

		// Extract the full template expression for the field description.
		fullExpr := extractTemplateExpr(line)

		risks = append(risks, types.TemplateRisk{
			File:     relPath,
			Line:     lineNum,
			Kind:     "CONDITIONAL_SECURITY",
			Field:    fullExpr,
			Severity: "MEDIUM",
			Description: "Security component (" + fieldName + ") is only deployed when " +
				fullExpr + " is set. If this CRD field is optional, the component is absent by default.",
		})
	}
	return risks
}

// checkHardcodedCredential looks for literal password/secret values in YAML.
func checkHardcodedCredential(trimmedLine, relPath string, lineNum int) []types.TemplateRisk {
	matches := hardcodedSecretPattern.FindStringSubmatch(trimmedLine)
	if len(matches) < 2 {
		return nil
	}

	value := matches[1]

	// Skip template variables and common placeholders.
	if strings.Contains(value, "{{") || strings.Contains(value, "$(") {
		return nil
	}
	if strings.EqualFold(value, "changeme") || strings.EqualFold(value, "CHANGEME") {
		// Still flag "changeme" as it's a hardcoded credential, just a weak one.
	}

	return []types.TemplateRisk{
		{
			File:        relPath,
			Line:        lineNum,
			Kind:        "HARDCODED_CREDENTIAL",
			Field:       strings.SplitN(trimmedLine, ":", 2)[0],
			Severity:    "HIGH",
			Description: "Hardcoded credential value found. Secrets should be sourced from Secret resources or external secret stores, not embedded in template files.",
		},
	}
}

// checkBase64Secret looks for base64-encoded values in Secret manifests.
func checkBase64Secret(trimmedLine, relPath string, lineNum int) []types.TemplateRisk {
	// Skip lines that are template expressions, comments, or metadata fields.
	if strings.Contains(trimmedLine, "{{") || strings.HasPrefix(trimmedLine, "#") {
		return nil
	}
	if strings.HasPrefix(trimmedLine, "kind:") || strings.HasPrefix(trimmedLine, "apiVersion:") ||
		strings.HasPrefix(trimmedLine, "name:") || strings.HasPrefix(trimmedLine, "namespace:") ||
		strings.HasPrefix(trimmedLine, "type:") || strings.HasPrefix(trimmedLine, "metadata:") ||
		strings.HasPrefix(trimmedLine, "data:") || strings.HasPrefix(trimmedLine, "stringData:") {
		return nil
	}

	if !base64SecretPattern.MatchString(trimmedLine) {
		return nil
	}

	return []types.TemplateRisk{
		{
			File:        relPath,
			Line:        lineNum,
			Kind:        "HARDCODED_CREDENTIAL",
			Field:       strings.SplitN(trimmedLine, ":", 2)[0],
			Severity:    "MEDIUM",
			Description: "Base64-encoded secret value in Secret manifest. Hardcoded secrets should be replaced with references to external secret stores.",
		},
	}
}

// extractTemplateExpr extracts the Go template field expression from a line
// (e.g. ".Spec.KubeRBACProxy" from "{{ if .Spec.KubeRBACProxy }}").
func extractTemplateExpr(line string) string {
	re := regexp.MustCompile(`\{\{-?\s*if\s+(\.(?:[A-Za-z]+\.)*[A-Za-z]+)\s*\}\}`)
	matches := re.FindStringSubmatch(line)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

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
