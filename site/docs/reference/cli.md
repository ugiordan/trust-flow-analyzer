# CLI Commands

## `analyze`

Run trust flow analysis on a project. Supports Go, Python, TypeScript, and Rust. The language is auto-detected from project marker files (`go.mod`, `pyproject.toml`, `package.json`, `Cargo.toml`).

```bash
trust-flow-analyzer analyze [flags] <directory>
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-output` | `trust-flow-map.md` | Output file path |
| `-format` | `markdown` | Output format: `markdown` or `json` |
| `-arch-context` | _(none)_ | Path to architecture-analyzer JSON output for component boundary scoping |

### Output formats

**Markdown** (`-format markdown`): human-readable report designed to be consumed by LLM agents via `--context trust-flow=path/to/map.md`. This is the default.

**JSON** (`-format json`): machine-readable output containing the full `AnalysisResult` structure. Useful for programmatic consumption, CI pipelines, and integration with other tools.

```bash
# JSON output to stdout
trust-flow-analyzer analyze -format json -output - /path/to/repo

# JSON output to file
trust-flow-analyzer analyze -format json -output results.json /path/to/repo
```

### Architecture context integration

The `--arch-context` flag accepts a path to an architecture-analyzer JSON output file. When provided, the tool uses component boundary information to:

- Scope findings to specific architectural components
- Enrich contradiction reports with component ownership
- Detect cross-component trust assumptions

```bash
# First, generate architecture context
arch-analyzer scan /path/to/repo -output arch.json

# Then run trust-flow analysis with arch context
trust-flow-analyzer analyze --arch-context arch.json /path/to/repo
```

### Examples

```bash
# Analyze current directory (language auto-detected)
trust-flow-analyzer analyze .

# Analyze with custom output path
trust-flow-analyzer analyze -output security-report.md /path/to/repo

# Analyze a specific Go project
trust-flow-analyzer analyze ~/code/my-operator

# Analyze a Python project with JSON output
trust-flow-analyzer analyze -format json ~/code/my-flask-app

# Analyze with architecture context
trust-flow-analyzer analyze --arch-context arch.json /path/to/repo
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Analysis completed (findings may or may not exist) |
| 1 | Error (package loading failed, invalid arguments, etc.) |

## `version`

Print the version string.

```bash
trust-flow-analyzer version
```

## `help`

Print usage information.

```bash
trust-flow-analyzer help
```
