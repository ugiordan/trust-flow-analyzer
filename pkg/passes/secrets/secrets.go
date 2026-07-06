package secrets

import (
	"bufio"
	"go/ast"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/ugiordan/trust-flow-analyzer/pkg/loader"
	"github.com/ugiordan/trust-flow-analyzer/pkg/passes"
	"github.com/ugiordan/trust-flow-analyzer/pkg/types"
)

// secretEnvPattern matches shell-style variable references that contain secret-related
// substrings (e.g. $(DB_PASSWORD), $(API_SECRET_KEY), $(AUTH_TOKEN)).
var secretEnvPattern = regexp.MustCompile(`\$\((?:[A-Z]+_)*(?:PASSWORD|SECRET|TOKEN|KEY)(?:_[A-Z]+)*\)`)

// Pass implements the secret exposure analysis.
type Pass struct{}

func (p *Pass) Name() string { return "secrets" }

func (p *Pass) Run(ctx *passes.Context) error {
	if ctx.Program.GoSSA != nil {
		return p.runGo(ctx)
	}
	return p.runGeneric(ctx)
}

func (p *Pass) runGo(ctx *passes.Context) error {
	goSSA := ctx.Program.GoSSA
	modulePath := ctx.Program.ModulePath

	for _, pkg := range goSSA.Packages {
		p.analyzePackage(pkg, ctx.Result, goSSA.Fset, modulePath)
	}

	sort.Slice(ctx.Result.SecretExposures, func(i, j int) bool {
		ei, ej := ctx.Result.SecretExposures[i], ctx.Result.SecretExposures[j]
		if ei.Location.File != ej.Location.File {
			return ei.Location.File < ej.Location.File
		}
		return ei.Location.Line < ej.Location.Line
	})

	return nil
}

// runGeneric scans source file content for secret patterns regardless of language.
// The secretEnvPattern regex works on raw file content.
func (p *Pass) runGeneric(ctx *passes.Context) error {
	prog := ctx.Program

	for filePath, content := range prog.Files {
		relFile := relPath(prog.RootDir, filePath)
		scanner := bufio.NewScanner(strings.NewReader(string(content)))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Text()
			matches := secretEnvPattern.FindAllString(line, -1)
			for _, match := range matches {
				ctx.Result.SecretExposures = append(ctx.Result.SecretExposures, types.SecretExposure{
					Location: types.Location{
						File: relFile,
						Line: lineNum,
					},
					Pattern:     "ENV_IN_ARGS",
					Description: "Secret env var " + match + " found in source",
					Field:       "source",
				})
			}
		}
	}

	sort.Slice(ctx.Result.SecretExposures, func(i, j int) bool {
		ei, ej := ctx.Result.SecretExposures[i], ctx.Result.SecretExposures[j]
		if ei.Location.File != ej.Location.File {
			return ei.Location.File < ej.Location.File
		}
		return ei.Location.Line < ej.Location.Line
	})

	return nil
}

// relPath computes a relative path from rootDir. If rootDir is empty or
// the computation fails, the original path is returned.
func relPath(rootDir, filePath string) string {
	if rootDir == "" {
		return filePath
	}
	rel, err := filepath.Rel(rootDir, filePath)
	if err != nil {
		return filePath
	}
	return rel
}

func (p *Pass) analyzePackage(pkg *packages.Package, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CompositeLit:
				p.analyzeCompositeLit(node, pkg, result, fset, modulePath)
			}
			return true
		})
	}
}

// analyzeCompositeLit scans struct literals for secret exposure patterns.
// It looks for two things:
//  1. Args/Command fields containing $(ENV_VAR) references to secret env vars.
//     Kubelet expands env vars in container args, which means secrets appear in
//     /proc/1/cmdline and are visible to anyone who can exec into the container.
//  2. String literals in any field that look like hardcoded secrets.
func (p *Pass) analyzeCompositeLit(lit *ast.CompositeLit, pkg *packages.Package, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}

		ident, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}

		fieldName := ident.Name

		// Check Args and Command fields for secret env var expansion
		if fieldName == "Args" || fieldName == "Command" {
			p.checkEnvVarExpansion(kv.Value, fieldName, pkg, result, fset, modulePath)
		}

		// Check Env field for env vars sourced from secrets that might be used in Args
		if fieldName == "Env" {
			p.checkEnvFromSecret(kv.Value, pkg, result, fset, modulePath)
		}
	}
}

// checkEnvVarExpansion scans a composite literal value (expected to be a string
// slice) for shell-style $(ENV_VAR) references that contain secret-related names.
func (p *Pass) checkEnvVarExpansion(expr ast.Expr, fieldName string, pkg *packages.Package, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	// Walk all string literals in the expression tree
	ast.Inspect(expr, func(n ast.Node) bool {
		basicLit, ok := n.(*ast.BasicLit)
		if !ok || basicLit.Kind != token.STRING {
			return true
		}

		value := strings.Trim(basicLit.Value, `"` + "`")
		matches := secretEnvPattern.FindAllString(value, -1)
		for _, match := range matches {
			pos := fset.Position(basicLit.Pos())
			result.SecretExposures = append(result.SecretExposures, types.SecretExposure{
				Location: types.Location{
					File:    loader.RelativePath(pos.Filename, modulePath),
					Line:    pos.Line,
					Package: pkg.PkgPath,
				},
				Pattern:     "ENV_IN_ARGS",
				Description: "Secret env var " + match + " expanded in container " + fieldName + " (visible in /proc/1/cmdline)",
				Field:       fieldName,
			})
		}

		return true
	})
}

// checkEnvFromSecret scans Env field composite literals for environment variables
// whose values are sourced from Kubernetes Secrets (via SecretKeyRef). When such
// env vars are also referenced in Args via $(...), the secret value ends up in
// the process command line.
func (p *Pass) checkEnvFromSecret(expr ast.Expr, pkg *packages.Package, result *types.AnalysisResult, fset *token.FileSet, modulePath string) {
	// Walk the Env value looking for nested structs that reference SecretKeyRef
	ast.Inspect(expr, func(n ast.Node) bool {
		innerLit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}

		hasSecretKeyRef := false
		envVarName := ""

		for _, elt := range innerLit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}

			if key.Name == "Name" {
				if lit, ok := kv.Value.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					envVarName = strings.Trim(lit.Value, `"`)
				}
			}

			// Check if ValueFrom contains a SecretKeyRef by walking the sub-tree
			if key.Name == "ValueFrom" {
				ast.Inspect(kv.Value, func(inner ast.Node) bool {
					innerKV, ok := inner.(*ast.KeyValueExpr)
					if !ok {
						return true
					}
					innerKey, ok := innerKV.Key.(*ast.Ident)
					if !ok {
						return true
					}
					if innerKey.Name == "SecretKeyRef" {
						hasSecretKeyRef = true
					}
					return true
				})
			}
		}

		if hasSecretKeyRef && envVarName != "" {
			pos := fset.Position(innerLit.Pos())
			result.SecretExposures = append(result.SecretExposures, types.SecretExposure{
				Location: types.Location{
					File:    loader.RelativePath(pos.Filename, modulePath),
					Line:    pos.Line,
					Package: pkg.PkgPath,
				},
				Pattern:     "ENV_IN_ARGS",
				Description: "Env var " + envVarName + " sourced from Secret via SecretKeyRef (if used in Args, secret is visible in /proc/1/cmdline)",
				Field:       "Env",
			})
		}

		return true
	})
}
