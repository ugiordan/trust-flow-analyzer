# Installation

## Release binaries

Pre-built binaries for v0.1.0 are available on the [GitHub releases page](https://github.com/ugiordan/trust-flow-analyzer/releases/tag/v0.1.0).

Download the binary for your platform:

```bash
# Linux amd64
curl -Lo trust-flow-analyzer https://github.com/ugiordan/trust-flow-analyzer/releases/download/v0.1.0/trust-flow-analyzer-linux-amd64
chmod +x trust-flow-analyzer
sudo mv trust-flow-analyzer /usr/local/bin/

# macOS arm64
curl -Lo trust-flow-analyzer https://github.com/ugiordan/trust-flow-analyzer/releases/download/v0.1.0/trust-flow-analyzer-darwin-arm64
chmod +x trust-flow-analyzer
sudo mv trust-flow-analyzer /usr/local/bin/
```

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

- Go 1.26 or later
- For Go project analysis: the target project must have a `go.mod` file, and the Go version used to build trust-flow-analyzer must be >= the Go version required by the target project
- For Python, TypeScript, and Rust analysis: no additional requirements (tree-sitter grammars are embedded in the binary)
