# trust-flow-analyzer

Deterministic extraction of cross-file trust and dependency flows from Go source code. No LLM calls. Same output every run.

## What it does

Extracts **what components assume about each other**, not just whether data flows between them. CodeQL can tell you "data flows from A to B." trust-flow-analyzer tells you "A assumes B validates the data, but B doesn't."

### Five analysis passes

1. **AuthFlow**: traces credential arrival to access decision, groups into distinct paths, determines if each path has authentication, authorization, or both
2. **DefaultValue**: finds what empty/nil/zero means at each configuration level, cross-references with platform semantics (K8s API)
3. **Contract**: for exported functions returning errors, checks if all callers handle the error
4. **ErrorProp**: traces error values from creation to handling, flags dropped errors and fail-open paths
5. **Lifecycle**: traces K8s resource creation, ownership, and cleanup

### Contradiction synthesis

After all passes run, the synthesizer detects cross-file assumption violations:
- Auth paths with authentication but no authorization
- Multiple security-critical fields defaulting to permissive values
- Dropped errors on authentication/authorization code paths
- Resources created without ownership or cleanup mechanisms

## Usage

```bash
trust-flow-analyzer analyze /path/to/go/project
trust-flow-analyzer analyze --output report.md /path/to/go/project
```

## Building

```bash
make build
make test
```

## How it works

Uses `golang.org/x/tools/go/packages` for type-checked package loading, SSA (Static Single Assignment) form for interprocedural analysis, and VTA (Variable Type Analysis) for precise call graph construction. Same stack as govulncheck.

Analysis is scoped to the target module only (stdlib and vendored dependencies are excluded from findings).

## Output format

Produces a markdown trust flow map with sections for each analysis domain and a final "Assumption Contradictions" section that flags cross-file issues.

## Integration

- **architecture-analyzer**: optionally takes arch-analyzer output as input for component boundary scoping
- **adversarial-reviewing**: produces `trust-flow-map.md` consumed via `--context trust-flow=path/to/map.md`
- **code-claim-verifier**: provides ground truth for CCV to check agent claims against
