# Installation

## From source

```bash
git clone https://github.com/ugiordan/trust-flow-analyzer.git
cd trust-flow-analyzer
make build
```

The binary `trust-flow-analyzer` will be created in the project root.

## With `go install`

```bash
go install github.com/ugiordan/trust-flow-analyzer/cmd/trust-flow-analyzer@latest
```

## Requirements

- Go 1.23 or later (1.25+ recommended for analyzing projects that require it)
- The target project must have a `go.mod` file
- The Go version used to build trust-flow-analyzer must be >= the Go version required by the target project
