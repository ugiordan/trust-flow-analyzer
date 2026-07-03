package secrets

import (
	"go/ast"
	"go/token"
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
var secretEnvPattern = regexp.MustCompile(`\$\([A-Z_]*(?:PASSWORD|SECRET|TOKEN|KEY)[A-Z_]*\)`)

// Pass implements the secret exposure analysis.
type Pass struct{}

func (p *Pass) Name() string { return "secrets" }

func (p *Pass) Run(ctx *passes.Context) error {
	for _, pkg := range ctx.Program.Packages {
		p.analyzePackage(pkg, ctx.Result, ctx.Program.Fset, ctx.Program.ModulePath)
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
