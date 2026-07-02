# CLI Commands

## `analyze`

Run trust flow analysis on a Go project.

```bash
trust-flow-analyzer analyze [flags] <directory>
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-output` | `trust-flow-map.md` | Output file path |
| `-format` | `markdown` | Output format (only markdown supported in v1) |
| `-arch-context` | _(none)_ | Path to architecture-analyzer output (planned, not yet implemented) |

### Examples

```bash
# Analyze current directory
trust-flow-analyzer analyze .

# Analyze with custom output path
trust-flow-analyzer analyze -output security-report.md /path/to/repo

# Analyze a specific project
trust-flow-analyzer analyze ~/code/my-operator
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
