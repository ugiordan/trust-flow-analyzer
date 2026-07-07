# trust-flow-analyzer

[![CI](https://github.com/ugiordan/trust-flow-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/ugiordan/trust-flow-analyzer/actions/workflows/ci.yml)

Deterministic extraction of cross-file trust and dependency flows from source code. Supports Go (via SSA+VTA) and Python (via tree-sitter). No LLM calls. Same output every run.

**[Documentation](https://ugiordan.github.io/trust-flow-analyzer/)**

## What it does

Extracts **what components assume about each other**, not just whether data flows between them. CodeQL can tell you "data flows from A to B." trust-flow-analyzer tells you "A assumes B validates the data, but B doesn't."

### Six analysis passes

1. **AuthFlow**: traces credential arrival to access decision, groups into distinct paths, determines posture (PERMISSIVE vs RESTRICTIVE)
2. **DefaultValue**: finds what empty/nil/zero means at each configuration level, cross-references with K8s platform semantics. Scans kubebuilder annotations and optional security component fields.
3. **Contract**: for functions returning errors, checks if all callers handle the error
4. **ErrorProp**: traces error values from creation to handling, flags dropped errors and fail-open paths
5. **Lifecycle**: traces K8s resource creation, ownership, and cleanup. Detects orphanable resources.
6. **Secrets**: detects secret exposure patterns (env vars in container args, hardcoded credentials)

### Contradiction synthesis

After all passes run, the synthesizer detects cross-file assumption violations:
- Auth paths with authentication but no authorization
- Multiple security-critical fields defaulting to permissive values
- Dropped errors on authentication/authorization code paths
- Resources created without ownership or cleanup mechanisms

## Quick start

```bash
go install github.com/ugiordan/trust-flow-analyzer/cmd/trust-flow-analyzer@latest
trust-flow-analyzer analyze /path/to/project
```

Or download a binary from the [releases page](https://github.com/ugiordan/trust-flow-analyzer/releases).

## Multi-language support

| Language | Backend | Precision |
|----------|---------|-----------|
| Go | SSA + VTA call graph | High (type-resolved, interface dispatch) |
| Python | tree-sitter + heuristic call graph | Medium (name-based resolution) |

Language is auto-detected from project files (go.mod, pyproject.toml, package.json, Cargo.toml).

## Building

```bash
make build
make test
```

## How it works

For Go repos, uses `golang.org/x/tools/go/packages` for type-checked loading, SSA for interprocedural analysis, and VTA for precise call graph construction. Same stack as govulncheck.

For Python repos, uses tree-sitter for AST extraction with heuristic name-based call graph construction.

Analysis is scoped to the target module only (stdlib and vendored dependencies are excluded from findings).

## Integration

- **adversarial-reviewing**: produces `trust-flow-map.md` consumed via `--context trust-flow=path/to/map.md`
- **architecture-analyzer**: optionally takes arch-analyzer output via `--arch-context`
- **code-claim-verifier**: provides ground truth for CCV to check agent claims against

## License

Apache 2.0
