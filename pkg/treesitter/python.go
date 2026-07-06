package treesitter

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/ugiordan/trust-flow-analyzer/pkg/ir"
)

// MaxFileSize is the largest file the parser will attempt (5 MB).
const MaxFileSize = 5 * 1024 * 1024

// PythonParser extracts trust-flow IR from Python source files using tree-sitter.
// Each goroutine MUST use its own instance (tree-sitter parsers are not thread-safe).
type PythonParser struct {
	parser  *sitter.Parser
	rootDir string // project root for deriving package names
}

// NewPythonParser creates a parser for Python source files.
// rootDir is the project root used to compute package paths from file paths.
func NewPythonParser(rootDir string) *PythonParser {
	p := sitter.NewParser()
	p.SetLanguage(python.GetLanguage())
	return &PythonParser{parser: p, rootDir: rootDir}
}

func (pp *PythonParser) Language() string     { return "python" }
func (pp *PythonParser) Extensions() []string { return []string{".py"} }

// Clone returns a new PythonParser for use in a separate goroutine.
func (pp *PythonParser) Clone() Parser {
	return NewPythonParser(pp.rootDir)
}

// ParseFile parses a Python source file and returns extracted functions, call sites,
// decorators, and error patterns.
func (pp *PythonParser) ParseFile(path string, content []byte) (*FileResult, error) {
	if len(content) > MaxFileSize {
		return nil, fmt.Errorf("file too large (%d bytes, max %d)", len(content), MaxFileSize)
	}
	tree, err := pp.parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		return nil, fmt.Errorf("tree-sitter parse failed: %w", err)
	}
	defer tree.Close()

	result := &FileResult{}
	root := tree.RootNode()

	pkg := pp.packageFromPath(path)
	w := &pythonWalker{
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
// For example, "src/auth/handlers.py" becomes "src.auth".
func (pp *PythonParser) packageFromPath(path string) string {
	rel, err := filepath.Rel(pp.rootDir, path)
	if err != nil {
		rel = path
	}
	dir := filepath.Dir(rel)
	if dir == "." || dir == "" {
		return ""
	}
	return strings.ReplaceAll(dir, string(filepath.Separator), ".")
}

// pythonWalker carries state during a depth-first walk of the AST.
type pythonWalker struct {
	src      []byte
	file     string
	pkg      string
	result   *FileResult
	curFunc  string // enclosing function ID (for call site caller attribution)
	curClass string // enclosing class name (for method attribution)
}

func (w *pythonWalker) walk(node *sitter.Node) {
	if node == nil {
		return
	}

	switch node.Type() {
	case "class_definition":
		w.extractClass(node)
		return // children handled inside
	case "decorated_definition":
		w.extractDecorated(node)
		return // children handled inside
	case "function_definition":
		w.extractFunction(node, nil)
		return // children handled inside
	case "call":
		w.extractCallSite(node)
	case "raise_statement":
		w.extractRaise(node)
	case "try_statement":
		w.extractTryExcept(node)
	}

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			w.walk(child)
		}
	}
}

// extractClass processes a class_definition: sets the class context, walks the body.
func (w *pythonWalker) extractClass(node *sitter.Node) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	className := nameNode.Content(w.src)

	prevClass := w.curClass
	w.curClass = className

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
}

// extractDecorated handles a decorated_definition: collects decorator text, then
// delegates to extractFunction for the inner function_definition.
func (w *pythonWalker) extractDecorated(node *sitter.Node) {
	var decorators []string
	var fnNode *sitter.Node

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "decorator":
			decorators = append(decorators, child.Content(w.src))
		case "function_definition":
			fnNode = child
		case "class_definition":
			// decorated class: walk with normal class extraction
			w.extractClass(child)
			return
		}
	}

	if fnNode != nil {
		w.extractFunction(fnNode, decorators)
	}
}

// extractFunction creates an ir.FunctionInfo and walks the body for nested constructs.
func (w *pythonWalker) extractFunction(node *sitter.Node, decorators []string) {
	nameNode := node.ChildByFieldName("name")
	if nameNode == nil {
		return
	}
	name := nameNode.Content(w.src)
	line := int(node.StartPoint().Row) + 1
	endLine := int(node.EndPoint().Row) + 1

	// Build function ID: "pkg.ClassName.FuncName" or "pkg.FuncName"
	id := w.functionID(name)

	isMethod := w.curClass != ""
	isExported := len(name) > 0 && !strings.HasPrefix(name, "_")

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

	// Extract return type annotation if present
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
func (w *pythonWalker) extractParams(params *sitter.Node) []ir.ParamInfo {
	var result []ir.ParamInfo
	for i := 0; i < int(params.ChildCount()); i++ {
		param := params.Child(i)
		if param == nil {
			continue
		}

		var pName, pType string
		switch param.Type() {
		case "identifier":
			pName = param.Content(w.src)
		case "typed_parameter":
			if n := param.ChildByFieldName("name"); n != nil {
				pName = n.Content(w.src)
			} else {
				pName = firstIdentifier(param, w.src)
			}
			if t := param.ChildByFieldName("type"); t != nil {
				pType = t.Content(w.src)
			}
		case "typed_default_parameter":
			if n := param.ChildByFieldName("name"); n != nil {
				pName = n.Content(w.src)
			} else {
				pName = firstIdentifier(param, w.src)
			}
			if t := param.ChildByFieldName("type"); t != nil {
				pType = t.Content(w.src)
			}
		case "default_parameter":
			if n := param.ChildByFieldName("name"); n != nil {
				pName = n.Content(w.src)
			} else {
				pName = firstIdentifier(param, w.src)
			}
		case "list_splat_pattern", "dictionary_splat_pattern":
			pName = firstIdentifier(param, w.src)
			if param.Type() == "list_splat_pattern" {
				pName = "*" + pName
			} else {
				pName = "**" + pName
			}
		}

		// Skip self/cls
		if pName == "" || pName == "self" || pName == "cls" {
			continue
		}

		result = append(result, ir.ParamInfo{Name: pName, Type: pType})
	}
	return result
}

// extractCallSite creates an ir.CallSiteInfo from a call expression.
func (w *pythonWalker) extractCallSite(node *sitter.Node) {
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
	if fnNode.Type() == "attribute" {
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
func (w *pythonWalker) extractArguments(args *sitter.Node) []string {
	var result []string
	for i := 0; i < int(args.ChildCount()); i++ {
		arg := args.Child(i)
		if arg == nil {
			continue
		}
		// Skip punctuation tokens (commas, parens)
		switch arg.Type() {
		case "(", ")", ",":
			continue
		case "keyword_argument":
			// Include as "key=value"
			result = append(result, arg.Content(w.src))
		default:
			result = append(result, arg.Content(w.src))
		}
	}
	return result
}

// extractRaise handles raise statements.
func (w *pythonWalker) extractRaise(node *sitter.Node) {
	line := int(node.StartPoint().Row) + 1
	msg := ""

	// Try to get the exception text
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() != "raise" {
			msg = child.Content(w.src)
			break
		}
	}

	w.result.Errors = append(w.result.Errors, ErrorPattern{
		Kind:     "raise",
		File:     w.file,
		Line:     line,
		FuncName: functionNameFromID(w.curFunc),
		Message:  msg,
	})
}

// extractTryExcept scans a try_statement for empty except blocks (errors dropped).
func (w *pythonWalker) extractTryExcept(node *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child == nil {
			continue
		}

		if child.Type() == "except_clause" {
			if isEmptyExceptBody(child) {
				line := int(child.StartPoint().Row) + 1
				w.result.Errors = append(w.result.Errors, ErrorPattern{
					Kind:     "empty_except",
					File:     w.file,
					Line:     line,
					FuncName: functionNameFromID(w.curFunc),
					Message:  "empty except block swallows error",
				})
			}
		}
	}

	// Walk children normally so we pick up calls/raises inside try/except bodies
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			// Walk the block children (try body, except body, finally body)
			// but not the try_statement itself (to avoid infinite recursion)
			switch child.Type() {
			case "block":
				for j := 0; j < int(child.ChildCount()); j++ {
					gc := child.Child(j)
					if gc != nil {
						w.walk(gc)
					}
				}
			case "except_clause", "finally_clause", "else_clause":
				for j := 0; j < int(child.ChildCount()); j++ {
					gc := child.Child(j)
					if gc != nil && gc.Type() == "block" {
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
}

// isEmptyExceptBody returns true if an except_clause body contains only "pass"
// or is completely empty (error is silently swallowed).
func isEmptyExceptBody(exceptNode *sitter.Node) bool {
	var bodyNode *sitter.Node
	for i := 0; i < int(exceptNode.ChildCount()); i++ {
		child := exceptNode.Child(i)
		if child != nil && child.Type() == "block" {
			bodyNode = child
			break
		}
	}
	if bodyNode == nil {
		return true
	}

	// Check if body has only pass statements or comments
	hasStatements := false
	for i := 0; i < int(bodyNode.ChildCount()); i++ {
		child := bodyNode.Child(i)
		if child == nil {
			continue
		}
		switch child.Type() {
		case "pass_statement", "comment", "expression_statement":
			// expression_statement with just "..." (ellipsis) counts as empty
			if child.Type() == "expression_statement" {
				inner := child.Child(0)
				if inner != nil && inner.Type() == "ellipsis" {
					continue
				}
				hasStatements = true
			}
		default:
			hasStatements = true
		}
	}
	return !hasStatements
}

// functionID builds a unique function ID from the current context.
func (w *pythonWalker) functionID(name string) string {
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

// functionNameFromID extracts just the function name from a full ID like "pkg.Class.func".
func functionNameFromID(id string) string {
	if id == "" {
		return ""
	}
	parts := strings.Split(id, ".")
	return parts[len(parts)-1]
}

// firstIdentifier finds the first identifier child node and returns its text.
func firstIdentifier(node *sitter.Node, src []byte) string {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil && child.Type() == "identifier" {
			return child.Content(src)
		}
	}
	return ""
}
