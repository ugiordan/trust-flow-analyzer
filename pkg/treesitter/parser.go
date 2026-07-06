package treesitter

import "github.com/ugiordan/trust-flow-analyzer/pkg/ir"

// FileResult holds everything extracted from a single source file by a tree-sitter parser.
type FileResult struct {
	Functions  []ir.FunctionInfo
	CallSites  []ir.CallSiteInfo
	Decorators []DecoratorInfo
	Errors     []ErrorPattern
}

// DecoratorInfo captures a decorator applied to a function.
type DecoratorInfo struct {
	FuncName string
	Text     string
	File     string
	Line     int
}

// ErrorPattern describes an error handling pattern found in source code.
type ErrorPattern struct {
	Kind     string // "raise", "throw", "empty_except", "empty_catch", "unwrap"
	File     string
	Line     int
	FuncName string
	Message  string
}

// Parser extracts functions, call sites, decorators, and error patterns from source files.
// Each goroutine MUST use its own Parser instance (tree-sitter parsers are not thread-safe).
type Parser interface {
	ParseFile(path string, content []byte) (*FileResult, error)
	Language() string
	Extensions() []string
	Clone() Parser
}
