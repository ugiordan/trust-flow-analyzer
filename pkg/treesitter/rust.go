package treesitter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
)

// RustParser extracts trust-flow IR from Rust source files using tree-sitter.
// Each goroutine MUST use its own instance (tree-sitter parsers are not thread-safe).
type RustParser struct {
	parser  *sitter.Parser
	rootDir string
}

// NewRustParser creates a parser for Rust source files.
// rootDir is the project root used to compute package paths from file paths.
func NewRustParser(rootDir string) *RustParser {
	p := sitter.NewParser()
	p.SetLanguage(rust.GetLanguage())
	return &RustParser{parser: p, rootDir: rootDir}
}

func (rp *RustParser) Language() string     { return "rust" }
func (rp *RustParser) Extensions() []string { return []string{".rs"} }

// Clone returns a new RustParser for use in a separate goroutine.
func (rp *RustParser) Clone() Parser {
	return NewRustParser(rp.rootDir)
}

// ParseFile parses a Rust source file and returns extracted functions, call sites,
// decorators, and error patterns.
func (rp *RustParser) ParseFile(path string, content []byte) (*FileResult, error) {
	if len(content) > MaxFileSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", len(content), MaxFileSize)
	}
	tree, err := rp.parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse failed: %w", err)
	}
	defer tree.Close()

	result := &FileResult{}
	root := tree.RootNode()

	pkg := rp.packageFromPath(path)
	w := &rustWalker{
		src:      content,
		file:     path,
		pkg:      pkg,
		result:   result,
		curFunc:  "",
		curImpl:  "",
	}
	w.walk(root)
	return result, nil
}

// packageFromPath derives a dotted package name from a file path relative to rootDir.
func (rp *RustParser) packageFromPath(path string) string {
	rel, err := filepath.Rel(rp.rootDir, path)
	if err != nil {
		rel = path
	}
	dir := filepath.Dir(rel)
	if dir == "." || dir == "" {
		return ""
	}
	return strings.ReplaceAll(dir, string(filepath.Separator), ".")
}

// rustWalker carries state during a depth-first walk of the Rust AST.
type rustWalker struct {
	src    []byte
	file   string
	pkg    string
	result *FileResult
	curFunc string // enclosing function ID
	curImpl string // enclosing impl type name (for method attribution)
}

func (w *rustWalker) walk(node *sitter.Node) {
	if node == nil {
		return
	}

	switch node.Type() {
	case "impl_item":
		w.extractImpl(node)
		return
	case "function_item":
		w.extractFunction(node)
		return
	case "call_expression":
		w.extractCallSite(node)
	case "macro_invocation":
		w.extractMacro(node)
	case "try_expression":
		// ? operator usage: not an error per se, but we track it
		// No-op for now; the call inside will be picked up normally.
	}

	w.walkChildren(node)
}

func (w *rustWalker) walkChildren(node *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			w.walk(child)
		}
	}
}

// extractImpl processes an impl_item: sets the impl context and walks the body.
func (w *rustWalker) extractImpl(node *sitter.Node) {
	// Get the type being implemented.
	// impl_item structure: impl [TraitName for] TypeName { body }
	typeName := w.extractImplTypeName(node)
	if typeName == "" {
		// Fallback: use the type node
		typeNode := node.ChildByFieldName("type")
		if typeNode != nil {
			typeName = typeNode.Content(w.src)
		}
	}

	prevImpl := w.curImpl
	prevFunc := w.curFunc
	w.curImpl = typeName
	w.curFunc = ""

	body := node.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.ChildCount()); i++ {
			child := body.Child(i)
			if child != nil {
				w.walk(child)
			}
		}
	}

	w.curImpl = prevImpl
	w.curFunc = prevFunc
}

// extractImplTypeName extracts the type name from an impl_item.
// Handles both "impl TypeName" and "impl Trait for TypeName".
func (w *rustWalker) extractImplTypeName(node *sitter.Node) string {
	typeNode := node.ChildByFieldName("type")
	if typeNode != nil {
		return typeNode.Content(w.src)
	}
	// Fallback: look for type_identifier children
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == "type_identifier" {
			return child.Content(w.src)
		}
	}
	return ""
}

// extractFunction handles function_item nodes. Collects attributes (#[...]) as decorators.
func (w *rustWalker) extractFunction(node *sitter.Node) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nameNode.Content(w.src)
	line := int(node.StartPoint().Row) + 1
	endLine := int(node.EndPoint().Row) + 1

	// Collect attributes from preceding siblings
	attributes := w.collectAttributes(node)

	id := w.functionID(name)
	isMethod := w.curImpl != ""
	// Rust public items start with "pub"
	isExported := w.isPublic(node)

	fn := ir.FunctionInfo{
		ID:         id,
		Name:       name,
		File:       w.file,
		Line:       line,
		EndLine:    endLine,
		Package:    w.pkg,
		TypeName:   w.curImpl,
		Decorators: attributes,
		IsExported: isExported,
		IsMethod:   isMethod,
	}

	// Extract parameters
	params := node.ChildByFieldName("parameters")
	if params != nil {
		fn.Params = w.extractParams(params)
	}

	// Extract return type
	retType := node.ChildByFieldName("return_type")
	if retType != nil {
		fn.ReturnType = retType.Content(w.src)
	}

	w.result.Functions = append(w.result.Functions, fn)

	// Record attributes as decorators
	for _, attr := range attributes {
		w.result.Decorators = append(w.result.Decorators, DecoratorInfo{
			FuncName: name,
			Text:     attr,
			File:     w.file,
			Line:     line,
		})
	}

	// Walk body
	prevFunc := w.curFunc
	w.curFunc = id

	body := node.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.ChildCount()); i++ {
			child := body.Child(i)
			if child != nil {
				w.walk(child)
			}
		}
	}

	w.curFunc = prevFunc
}

// extractParams extracts parameter names and types from a Rust parameter list.
func (w *rustWalker) extractParams(params *sitter.Node) []ir.ParamInfo {
	var result []ir.ParamInfo
	for i := 0; i < int(params.ChildCount()); i++ {
		param := params.Child(i)
		if param == nil {
			continue
		}

		switch param.Type() {
		case "parameter":
			var pName, pType string
			patternNode := param.ChildByFieldName("pattern")
			if patternNode != nil {
				pName = patternNode.Content(w.src)
			}
			typeNode := param.ChildByFieldName("type")
			if typeNode != nil {
				pType = typeNode.Content(w.src)
			}
			if pName != "" {
				result = append(result, ir.ParamInfo{Name: pName, Type: pType})
			}
		case "self_parameter":
			// Skip &self, &mut self, self
			continue
		case "(", ")", ",":
			continue
		}
	}
	return result
}

// extractCallSite handles call_expression nodes.
// In Rust's tree-sitter grammar, method calls like x.unwrap() are represented as
// call_expression with a field_expression child (not method_call_expression).
func (w *rustWalker) extractCallSite(node *sitter.Node) {
	fnNode := node.ChildByFieldName("function")
	if fnNode == nil {
		return
	}

	callText := fnNode.Content(w.src)
	line := int(node.StartPoint().Row) + 1

	cs := ir.CallSiteInfo{
		CalleeName:   callText,
		File:         w.file,
		Line:         line,
		CallerFuncID: w.curFunc,
	}

	// Check for qualified path calls like Module::function
	if fnNode.Type() == "scoped_identifier" || fnNode.Type() == "field_expression" {
		cs.IsMethodCall = true
		// Extract the path prefix as receiver
		if fnNode.Type() == "field_expression" {
			obj := fnNode.ChildByFieldName("value")
			if obj != nil {
				cs.ReceiverExpr = obj.Content(w.src)
			}
			// Detect error-prone method calls: .unwrap(), .expect(), .panic()
			fieldNode := fnNode.ChildByFieldName("field")
			if fieldNode != nil {
				methodName := fieldNode.Content(w.src)
				switch methodName {
				case "unwrap":
					w.result.Errors = append(w.result.Errors, ErrorPattern{
						Kind:     "unwrap",
						File:     w.file,
						Line:     line,
						FuncName: functionNameFromID(w.curFunc),
						Message:  "unwrap() will panic on None/Err",
					})
				case "expect":
					msg := ""
					args := node.ChildByFieldName("arguments")
					if args != nil {
						for i := 0; i < int(args.ChildCount()); i++ {
							child := args.Child(i)
							if child != nil && child.Type() == "string_literal" {
								msg = child.Content(w.src)
								break
							}
						}
					}
					w.result.Errors = append(w.result.Errors, ErrorPattern{
						Kind:     "unwrap",
						File:     w.file,
						Line:     line,
						FuncName: functionNameFromID(w.curFunc),
						Message:  "expect() will panic: " + msg,
					})
				}
			}
		}
	}

	// Extract arguments
	args := node.ChildByFieldName("arguments")
	if args != nil {
		cs.Arguments = w.extractArguments(args)
	}

	w.result.CallSites = append(w.result.CallSites, cs)
}

// extractMacro handles macro_invocation nodes (panic!, todo!, etc.).
func (w *rustWalker) extractMacro(node *sitter.Node) {
	macroNode := node.ChildByFieldName("macro")
	if macroNode == nil {
		// Fallback: first identifier-like child
		for i := 0; i < int(node.ChildCount()); i++ {
			child := node.Child(i)
			if child != nil && (child.Type() == "identifier" || child.Type() == "scoped_identifier") {
				macroNode = child
				break
			}
		}
	}
	if macroNode == nil {
		return
	}

	macroName := macroNode.Content(w.src)
	line := int(node.StartPoint().Row) + 1

	switch macroName {
	case "panic":
		w.result.Errors = append(w.result.Errors, ErrorPattern{
			Kind:     "panic",
			File:     w.file,
			Line:     line,
			FuncName: functionNameFromID(w.curFunc),
			Message:  "panic! macro invocation",
		})
	case "todo":
		w.result.Errors = append(w.result.Errors, ErrorPattern{
			Kind:     "panic",
			File:     w.file,
			Line:     line,
			FuncName: functionNameFromID(w.curFunc),
			Message:  "todo! macro (will panic at runtime)",
		})
	case "unimplemented":
		w.result.Errors = append(w.result.Errors, ErrorPattern{
			Kind:     "panic",
			File:     w.file,
			Line:     line,
			FuncName: functionNameFromID(w.curFunc),
			Message:  "unimplemented! macro (will panic at runtime)",
		})
	}

	// Record as a call site for call graph purposes
	cs := ir.CallSiteInfo{
		CalleeName:   macroName + "!",
		File:         w.file,
		Line:         line,
		CallerFuncID: w.curFunc,
	}
	w.result.CallSites = append(w.result.CallSites, cs)
}

// extractArguments extracts string representations of call arguments.
func (w *rustWalker) extractArguments(args *sitter.Node) []string {
	var result []string
	for i := 0; i < int(args.ChildCount()); i++ {
		arg := args.Child(i)
		if arg == nil {
			continue
		}
		switch arg.Type() {
		case "(", ")", ",":
			continue
		default:
			result = append(result, arg.Content(w.src))
		}
	}
	return result
}

// collectAttributes gathers #[...] attribute nodes that precede a function_item.
// In Rust's tree-sitter grammar, attributes are siblings that precede the function.
func (w *rustWalker) collectAttributes(node *sitter.Node) []string {
	var attrs []string
	parent := node.Parent()
	if parent == nil {
		return nil
	}

	// Only collect contiguous attributes immediately before the target node.
	// Reset on any non-attribute sibling so attributes from a prior function
	// don't leak into this one.
	for i := 0; i < int(parent.ChildCount()); i++ {
		child := parent.Child(i)
		if child == nil {
			continue
		}
		if child == node {
			break
		}
		if child.Type() == "attribute_item" {
			attrs = append(attrs, child.Content(w.src))
		} else {
			attrs = attrs[:0] // reset: only contiguous attributes count
		}
	}
	return attrs
}

// isPublic checks whether a function_item has a "pub" visibility modifier.
func (w *rustWalker) isPublic(node *sitter.Node) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		if child.Type() == "visibility_modifier" {
			return true
		}
		// Stop at the function name; visibility comes before it
		if child.Type() == "identifier" || child.Type() == "fn" {
			break
		}
	}
	return false
}

// functionID builds a unique function ID from the current context.
func (w *rustWalker) functionID(name string) string {
	parts := []string{}
	if w.pkg != "" {
		parts = append(parts, w.pkg)
	}
	if w.curImpl != "" {
		parts = append(parts, w.curImpl)
	}
	parts = append(parts, name)
	return strings.Join(parts, ".")
}
