# Development Setup

## Prerequisites

- Go 1.23+ (1.25+ for analyzing projects that require it)
- Make

## Building

```bash
git clone https://github.com/ugiordan/trust-flow-analyzer.git
cd trust-flow-analyzer
make build
```

## Running tests

```bash
make test
```

## Running the linter

```bash
make lint
```

## Project structure

```
trust-flow-analyzer/
├── cmd/trust-flow-analyzer/    # CLI entry point
├── pkg/
│   ├── types/                  # Shared types
│   ├── loader/                 # Package loading + SSA + VTA
│   ├── platform/               # Platform knowledge DB
│   ├── passes/                 # Analysis passes
│   ├── synthesis/              # Contradiction detection
│   └── output/                 # Markdown renderer
├── testdata/basic/             # Test fixture project
├── Makefile
└── go.mod
```

## Test fixtures

The `testdata/basic/` directory contains a minimal Go project with:

- Two HTTP handlers (one with auth+authz, one with only auth)
- Auth functions (ValidateToken, Authorize, CheckGroups)
- Config with permissive defaults (AllowedGroups: nil, EmailDomain: "")

Running the analyzer on this fixture should produce 2 auth flows, 2 config defaults, 1 contract violation, and 2 contradictions.

## Docs

The documentation site uses MkDocs with Material theme:

```bash
cd site
pip install mkdocs-material mkdocs-glightbox
mkdocs serve
```
