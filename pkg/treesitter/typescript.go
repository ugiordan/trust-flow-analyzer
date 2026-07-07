package treesitter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/typescript/tsx"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
)

// TypeScriptParser extracts trust-flow IR from TypeScript/JavaScript source files
// using tree-sitter with the TSX grammar (superset of TS, handles both).
// Each goroutine MUST use its own instance (tree-sitter parsers are not thread-safe).
type TypeScriptParser struct {
	parser  *sitter.Parser
	rootDir string
}

// NewTypeScriptParser creates a parser for TypeScript/JavaScript source files.
// rootDir is the project root used to compute package paths from file paths.
func NewTypeScriptParser(rootDir string) *TypeScriptParser {
	p := sitter.NewParser()
	p.SetLanguage(tsx.GetLanguage())
	return &TypeScriptParser{parser: p, rootDir: rootDir}
}

func (tp *TypeScriptParser) Language() string     { return "typescript" }
func (tp *TypeScriptParser) Extensions() []string { return []string{".ts", ".tsx", ".js", ".jsx"} }

// Clone returns a new TypeScriptParser for use in a separate goroutine.
func (tp *TypeScriptParser) Clone() Parser {
	return NewTypeScriptParser(tp.rootDir)
}

// ParseFile parses a TypeScript/JavaScript source file and returns extracted
// functions, call sites, decorators, and error patterns.
func (tp *TypeScriptParser) ParseFile(path string, content []byte) (*FileResult, error) {
	if len(content) > MaxFileSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", len(content), MaxFileSize)
	}
	tree, err := tp.parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse failed: %w", err)
	}
	defer tree.Close()

	result := &FileResult{}
	root := tree.RootNode()

	pkg := tp.packageFromPath(path)
	w := &tsWalker{
		src:      content,
		file:     path,
		pkg:      pkg,
		result:   result,
		curFunc:  "",
		curClass: "",
	}
	w.walk(root)
	return result, nil
}

// packageFromPath derives a dotted package name from a file path relative to rootDir.
func (tp *TypeScriptParser) packageFromPath(path string) string {
	rel, err := filepath.Rel(tp.rootDir, path)
	if err != nil {
		rel = path
	}
	dir := filepath.Dir(rel)
	if dir == "." || dir == "" {
		return ""
	}
	return strings.ReplaceAll(dir, string(filepath.Separator), ".")
}

// tsWalker carries state during a depth-first walk of the TypeScript AST.
type tsWalker struct {
	src      []byte
	file     string
	pkg      string
	result   *FileResult
	curFunc  string // enclosing function ID
	curClass string // enclosing class name
}

func (w *tsWalker) walk(node *sitter.Node) {
	if node == nil {
		return
	}

	switch node.Type() {
	case "class_declaration":
		w.extractClass(node)
		return
	case "function_declaration":
		w.extractFunctionDecl(node)
		return
	case "method_definition":
		w.extractMethodDef(node)
		return
	case "lexical_declaration", "variable_declaration":
		// Check for arrow function assignments: const handler = () => {}
		w.extractVarDecl(node)
		return
	case "arrow_function", "function":
		// Handle anonymous callbacks passed as arguments to call expressions.
		// e.g., app.get("/path", async (req, res) => { ... })
		// Generate a synthetic function name from the enclosing call target + line number.
		if w.isCallbackArg(node) {
			w.extractCallbackFunction(node)
			return
		}
	case "call_expression":
		w.extractCallSite(node)
	case "throw_statement":
		w.extractThrow(node)
	case "try_statement":
		w.extractTryCatch(node)
		return
	case "export_statement":
		// Walk children to pick up exported functions/classes
		w.walkChildren(node)
		return
	}

	w.walkChildren(node)
}

func (w *tsWalker) walkChildren(node *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			w.walk(child)
		}
	}
}

// extractClass processes a class_declaration: sets the class context, collects
// decorators, and walks the body.
func (w *tsWalker) extractClass(node *sitter.Node) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nameNode.Content(w.src)

	// Collect decorators from preceding siblings (TypeScript decorators precede the class)
	decorators := w.collectDecorators(node)

	prevClass := w.curClass
	prevFunc := w.curFunc
	w.curClass = className
	w.curFunc = ""

	// Record class-level decorators (e.g., @Controller)
	for _, dec := range decorators {
		w.result.Decorators = append(w.result.Decorators, DecoratorInfo{
			FuncName: className,
			Text:     dec,
			File:     w.file,
			Line:     int(node.StartPoint().Row) + 1,
		})
	}

	body := node.ChildByFieldName("body")
	if body != nil {
		for i := 0; i < int(body.ChildCount()); i++ {
			child := body.Child(i)
			if child != nil {
				w.walk(child)
			}
		}
	}

	w.curClass = prevClass
	w.curFunc = prevFunc
}

// extractFunctionDecl handles function_declaration nodes.
func (w *tsWalker) extractFunctionDecl(node *sitter.Node) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nameNode.Content(w.src)
	decorators := w.collectDecorators(node)

	w.recordFunction(node, name, decorators)
}

// extractMethodDef handles method_definition nodes inside classes.
func (w *tsWalker) extractMethodDef(node *sitter.Node) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nameNode.Content(w.src)
	decorators := w.collectDecorators(node)

	w.recordFunction(node, name, decorators)
}

// extractVarDecl handles variable declarations that may contain arrow functions.
// e.g., const handler = async (req, res) => { ... }
func (w *tsWalker) extractVarDecl(node *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil || child.Type() != "variable_declarator" {
			continue
		}

		nameNode := child.ChildByFieldName("name")
		valueNode := child.ChildByFieldName("value")

		if nameNode == nil || valueNode == nil {
			continue
		}

		// Check if the value is an arrow function or function expression
		valueType := valueNode.Type()
		if valueType == "arrow_function" || valueType == "function" {
			name := nameNode.Content(w.src)
			w.recordFunction(valueNode, name, nil)
		} else {
			// Walk non-function values for call sites
			w.walk(valueNode)
		}
	}
}

// recordFunction creates an ir.FunctionInfo, records decorators, and walks the body.
func (w *tsWalker) recordFunction(node *sitter.Node, name string, decorators []string) {
	line := int(node.StartPoint().Row) + 1
	endLine := int(node.EndPoint().Row) + 1
	id := w.functionID(name)

	isMethod := w.curClass != ""
	isExported := isMethod || (len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z')
	if hasExportAncestor(node) {
		isExported = true
	}

	fn := ir.FunctionInfo{
		ID:         id,
		Name:       name,
		File:       w.file,
		Line:       line,
		EndLine:    endLine,
		Package:    w.pkg,
		TypeName:   w.curClass,
		Decorators: decorators,
		IsExported: isExported,
		IsMethod:   isMethod,
	}

	// Extract parameters
	params := node.ChildByFieldName("parameters")
	if params != nil {
		fn.Params = w.extractParams(params)
	}

	// Extract return type annotation
	retType := node.ChildByFieldName("return_type")
	if retType != nil {
		fn.ReturnType = retType.Content(w.src)
	}

	w.result.Functions = append(w.result.Functions, fn)

	// Record decorators
	for _, dec := range decorators {
		w.result.Decorators = append(w.result.Decorators, DecoratorInfo{
			FuncName: name,
			Text:     dec,
			File:     w.file,
			Line:     line,
		})
	}

	// Walk body with this function as the enclosing context
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

// extractParams extracts parameter names and type annotations from a parameter list.
func (w *tsWalker) extractParams(params *sitter.Node) []ir.ParamInfo {
	var result []ir.ParamInfo
	for i := 0; i < int(params.ChildCount()); i++ {
		param := params.Child(i)
		if param == nil {
			continue
		}

		var pName, pType string
		switch param.Type() {
		case "required_parameter", "optional_parameter":
			if n := param.ChildByFieldName("pattern"); n != nil {
				pName = n.Content(w.src)
			} else {
				pName = firstIdentifier(param, w.src)
			}
			if t := param.ChildByFieldName("type"); t != nil {
				pType = t.Content(w.src)
			}
		case "identifier":
			pName = param.Content(w.src)
		case "rest_pattern":
			pName = "..." + firstIdentifier(param, w.src)
		case "(", ")", ",":
			continue
		}

		if pName == "" || pName == "this" {
			continue
		}
		result = append(result, ir.ParamInfo{Name: pName, Type: pType})
	}
	return result
}

// extractCallSite creates an ir.CallSiteInfo from a call expression.
func (w *tsWalker) extractCallSite(node *sitter.Node) {
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

	// Determine if this is a method call (has a dot)
	if fnNode.Type() == "member_expression" {
		cs.IsMethodCall = true
		obj := fnNode.ChildByFieldName("object")
		if obj != nil {
			cs.ReceiverExpr = obj.Content(w.src)
		}
	}

	// Extract arguments
	args := node.ChildByFieldName("arguments")
	if args != nil {
		cs.Arguments = w.extractArguments(args)
	}

	w.result.CallSites = append(w.result.CallSites, cs)
}

// extractArguments extracts string representations of call arguments.
func (w *tsWalker) extractArguments(args *sitter.Node) []string {
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

// extractThrow handles throw statements.
func (w *tsWalker) extractThrow(node *sitter.Node) {
	line := int(node.StartPoint().Row) + 1
	msg := ""

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() != "throw" {
			msg = child.Content(w.src)
			break
		}
	}

	w.result.Errors = append(w.result.Errors, ErrorPattern{
		Kind:     "throw",
		File:     w.file,
		Line:     line,
		FuncName: functionNameFromID(w.curFunc),
		Message:  msg,
	})
}

// extractTryCatch scans a try_statement for empty catch blocks.
func (w *tsWalker) extractTryCatch(node *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "catch_clause" {
			body := child.ChildByFieldName("body")
			if body != nil && isEmptyTSBlock(body) {
				line := int(child.StartPoint().Row) + 1
				w.result.Errors = append(w.result.Errors, ErrorPattern{
					Kind:     "empty_catch",
					File:     w.file,
					Line:     line,
					FuncName: functionNameFromID(w.curFunc),
					Message:  "empty catch block swallows error",
				})
			}
		}
	}

	// Walk children for nested constructs
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		switch child.Type() {
		case "statement_block":
			// try body
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc != nil {
					w.walk(gc)
				}
			}
		case "catch_clause":
			body := child.ChildByFieldName("body")
			if body != nil {
				for j := 0; j < int(body.ChildCount()); j++ {
					gc := body.Child(j)
					if gc != nil {
						w.walk(gc)
					}
				}
			}
		case "finally_clause":
			for j := 0; j < int(child.ChildCount()); j++ {
				gc := child.Child(j)
				if gc != nil && gc.Type() == "statement_block" {
					for k := 0; k < int(gc.ChildCount()); k++ {
						ggc := gc.Child(k)
						if ggc != nil {
							w.walk(ggc)
						}
					}
				}
			}
		}
	}
}

// isEmptyTSBlock returns true if a statement_block contains only comments
// or is empty (between the braces).
func isEmptyTSBlock(block *sitter.Node) bool {
	hasStatements := false
	for i := 0; i < int(block.ChildCount()); i++ {
		child := block.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "{", "}", "comment":
			continue
		default:
			hasStatements = true
		}
	}
	return !hasStatements
}

// collectDecorators gathers decorator nodes that precede a function/class/method.
// In tree-sitter's TypeScript grammar, decorators are children of the parent node
// and appear as siblings before the decorated node.
func (w *tsWalker) collectDecorators(node *sitter.Node) []string {
	var decorators []string
	parent := node.Parent()
	if parent == nil {
		return nil
	}

	// For method_definition inside a class body, decorators are preceding siblings.
	// For top-level function/class, decorators are in export_statement or preceding siblings.
	// Reset on any non-decorator sibling so decorators from a prior method
	// don't leak into this one.
	for i := 0; i < int(parent.ChildCount()); i++ {
		child := parent.Child(i)
		if child == nil {
			continue
		}
		// Stop when we reach the node itself
		if child == node {
			break
		}
		if child.Type() == "decorator" {
			decorators = append(decorators, child.Content(w.src))
		} else {
			decorators = decorators[:0] // reset: only contiguous decorators count
		}
	}
	return decorators
}

// isCallbackArg returns true when node is an arrow_function or function expression
// inside the arguments of a call_expression (i.e., a callback).
func (w *tsWalker) isCallbackArg(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	// The parent should be "arguments" and grandparent "call_expression"
	if parent.Type() == "arguments" {
		gp := parent.Parent()
		return gp != nil && gp.Type() == "call_expression"
	}
	return false
}

// extractCallbackFunction creates a synthetic function entry for an arrow function
// or function expression used as a callback argument, then walks its body with
// curFunc set so that call sites inside the callback are properly attributed.
func (w *tsWalker) extractCallbackFunction(node *sitter.Node) {
	parent := node.Parent()     // arguments
	callExpr := parent.Parent() // call_expression

	// Build a synthetic name from the call target + line number
	callTarget := ""
	fnNode := callExpr.ChildByFieldName("function")
	if fnNode != nil {
		callTarget = fnNode.Content(w.src)
		// Simplify dotted targets: "app.get" -> "app.get"
		callTarget = strings.ReplaceAll(callTarget, ".", "_")
	}
	line := int(node.StartPoint().Row) + 1
	syntheticName := fmt.Sprintf("%s$callback_L%d", callTarget, line)

	w.recordFunction(node, syntheticName, nil)
}

// hasExportAncestor walks up the AST parent chain (up to 4 levels) looking for
// an export_statement node. This handles all export forms:
//   - export function foo() {}             (1 hop)
//   - export const foo = () => {}          (3 hops: arrow -> var_declarator -> lexical_decl -> export)
//   - export class Foo {}                  (1 hop)
func hasExportAncestor(node *sitter.Node) bool {
	p := node.Parent()
	for i := 0; i < 4 && p != nil; i++ {
		if p.Type() == "export_statement" {
			return true
		}
		p = p.Parent()
	}
	return false
}

// functionID builds a unique function ID from the current context.
func (w *tsWalker) functionID(name string) string {
	parts := []string{}
	if w.pkg != "" {
		parts = append(parts, w.pkg)
	}
	if w.curClass != "" {
		parts = append(parts, w.curClass)
	}
	parts = append(parts, name)
	return strings.Join(parts, ".")
}
