# Integration

trust-flow-analyzer produces pre-computed trust flow maps that other tools consume. No LLM calls, deterministic output.

## With adversarial-reviewing

The primary integration. The trust flow map gives review agents cross-file context they can't derive from single-file analysis.

```bash
trust-flow-analyzer analyze -output trust-flow-map.md /path/to/repo

# Then pass to adversarial-reviewing
adversarial-review --context trust-flow=trust-flow-map.md /path/to/repo
```

Each agent receives the full map:

- **SEC** agent focuses on auth flows and permissive defaults
- **CORR** agent focuses on contract violations and error propagation
- **ARCH** agent focuses on resource lifecycles and ownership chains

## With architecture-analyzer

trust-flow-analyzer can optionally take architecture-analyzer output as input for component boundary scoping.

```bash
arch-analyzer extract /path/to/repo -o arch-output.json
trust-flow-analyzer analyze -arch-context arch-output.json /path/to/repo
```

When component boundaries are available, the analysis is scoped to trace flows within and between identified components rather than across the entire codebase.

!!! note
    The `-arch-context` flag is planned but not yet implemented in v1.

## With code-claim-verifier

CCV can verify claims made by agents against the trust flow map as ground truth:

- `CALL_CHAIN` claims verified against auth flow paths
- `DEFAULT_VALUE` claims verified against the configuration defaults table
