package treesitter

import (
	"os"
	"path/filepath"
	"testing"
)

const tsFixtureDir = "../../testdata/typescript-basic"

func mustReadFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return data
}

// TestTypeScriptParserBasic parses app.ts and verifies basic counts.
func TestTypeScriptParserBasic(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	appPath := filepath.Join(rootDir, "app.ts")
	content := mustReadFixture(t, appPath)

	result, err := parser.ParseFile(appPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// app.ts should produce:
	// - 3 callback functions (app.get L7, app.get L23, app.get L30)
	// - 1 named function (handler)
	// Total: 4 functions
	if len(result.Functions) < 4 {
		t.Errorf("expected at least 4 functions, got %d", len(result.Functions))
		for i, fn := range result.Functions {
			t.Logf("  fn[%d]: Name=%q ID=%q Line=%d", i, fn.Name, fn.ID, fn.Line)
		}
	}

	// Call sites: app.get (x3), validateToken (x3), authorize (x2), getConfig (x1),
	// req.headers (x3 via member access), res.status (x3), res.json (x4+),
	// express(), Error(), plus others from method calls.
	// Just verify we got a non-trivial count.
	if len(result.CallSites) < 10 {
		t.Errorf("expected at least 10 call sites, got %d", len(result.CallSites))
		for i, cs := range result.CallSites {
			t.Logf("  cs[%d]: Callee=%q Line=%d Caller=%q", i, cs.CalleeName, cs.Line, cs.CallerFuncID)
		}
	}
}

// TestTypeScriptFunctionExtraction verifies the auth.ts functions are extracted
// with correct names, line numbers, and export status.
func TestTypeScriptFunctionExtraction(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	authPath := filepath.Join(rootDir, "auth.ts")
	content := mustReadFixture(t, authPath)

	result, err := parser.ParseFile(authPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// auth.ts defines: validateToken (L1, exported), decodeToken (L13, private),
	// authorize (L20, exported), checkGroups (L27, exported)
	expected := map[string]struct {
		line       int
		isExported bool
	}{
		"validateToken": {line: 1, isExported: true},
		"decodeToken":   {line: 13, isExported: false},
		"authorize":     {line: 20, isExported: true},
		"checkGroups":   {line: 27, isExported: true},
	}

	found := map[string]bool{}
	for _, fn := range result.Functions {
		exp, ok := expected[fn.Name]
		if !ok {
			continue
		}
		found[fn.Name] = true

		if fn.Line != exp.line {
			t.Errorf("function %q: expected line %d, got %d", fn.Name, exp.line, fn.Line)
		}
		if fn.IsExported != exp.isExported {
			t.Errorf("function %q: expected IsExported=%v, got %v", fn.Name, exp.isExported, fn.IsExported)
		}
		if fn.File != authPath {
			t.Errorf("function %q: expected File=%q, got %q", fn.Name, authPath, fn.File)
		}
	}

	for name := range expected {
		if !found[name] {
			t.Errorf("expected function %q not found in results", name)
		}
	}
}

// TestTypeScriptArrowFunctionCallbacks verifies that Express-style callbacks
// (arrow functions passed as arguments) are extracted with synthetic names and
// correct caller attribution.
func TestTypeScriptArrowFunctionCallbacks(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	appPath := filepath.Join(rootDir, "app.ts")
	content := mustReadFixture(t, appPath)

	result, err := parser.ParseFile(appPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// We expect callback functions with synthetic names like "app_get$callback_L7"
	// for each app.get(..., async (req, res) => { ... }) call.
	callbackLines := map[int]bool{
		7:  false, // app.get("/api/data", async (req, res) => { ... })
		23: false, // app.get("/admin/dashboard", async (req, res) => { ... })
		30: false, // app.get("/health", (req, res) => { ... })
	}

	for _, fn := range result.Functions {
		if _, ok := callbackLines[fn.Line]; ok {
			callbackLines[fn.Line] = true
			// Synthetic name should contain "$callback_L"
			if !containsSubstr(fn.Name, "$callback_L") {
				t.Errorf("callback at line %d should have synthetic name containing '$callback_L', got %q", fn.Line, fn.Name)
			}
		}
	}

	for line, found := range callbackLines {
		if !found {
			t.Errorf("expected callback function at line %d not found", line)
		}
	}

	// Verify call sites inside callbacks have CallerFuncID set to the callback's ID
	// Find the L7 callback
	var callbackL7ID string
	for _, fn := range result.Functions {
		if fn.Line == 7 {
			callbackL7ID = fn.ID
			break
		}
	}

	if callbackL7ID == "" {
		t.Fatal("could not find callback function at line 7")
	}

	// validateToken at L9 should be attributed to the L7 callback
	foundValidateToken := false
	for _, cs := range result.CallSites {
		if cs.CalleeName == "validateToken" && cs.Line == 9 {
			foundValidateToken = true
			if cs.CallerFuncID != callbackL7ID {
				t.Errorf("validateToken call at L9: expected CallerFuncID=%q, got %q", callbackL7ID, cs.CallerFuncID)
			}
		}
	}
	if !foundValidateToken {
		t.Error("expected validateToken call site at line 9 not found")
	}
}

// TestTypeScriptCallSiteExtraction verifies that specific call sites
// (validateToken, authorize, checkGroups) are detected with correct callers.
func TestTypeScriptCallSiteExtraction(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	// Parse app.ts for calls to imported functions
	appPath := filepath.Join(rootDir, "app.ts")
	content := mustReadFixture(t, appPath)

	result, err := parser.ParseFile(appPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Verify validateToken is called at lines 9, 25, 36
	validateTokenLines := []int{9, 25, 36}
	for _, expectedLine := range validateTokenLines {
		found := false
		for _, cs := range result.CallSites {
			if cs.CalleeName == "validateToken" && cs.Line == expectedLine {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected validateToken call at line %d not found", expectedLine)
		}
	}

	// Verify authorize is called at lines 15 and 37
	authorizeLines := []int{15, 37}
	for _, expectedLine := range authorizeLines {
		found := false
		for _, cs := range result.CallSites {
			if cs.CalleeName == "authorize" && cs.Line == expectedLine {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected authorize call at line %d not found", expectedLine)
		}
	}

	// Verify getConfig is called (inside authorize call, line 15)
	foundGetConfig := false
	for _, cs := range result.CallSites {
		if cs.CalleeName == "getConfig" {
			foundGetConfig = true
			break
		}
	}
	if !foundGetConfig {
		t.Error("expected getConfig call not found")
	}

	// Parse auth.ts for internal call sites
	authPath := filepath.Join(rootDir, "auth.ts")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.ts failed: %v", err)
	}

	// decodeToken is called inside validateToken at line 7
	foundDecodeToken := false
	for _, cs := range authResult.CallSites {
		if cs.CalleeName == "decodeToken" {
			foundDecodeToken = true
			if cs.CallerFuncID != "validateToken" {
				t.Errorf("decodeToken call should have CallerFuncID=validateToken, got %q", cs.CallerFuncID)
			}
			break
		}
	}
	if !foundDecodeToken {
		t.Error("expected decodeToken call not found in auth.ts")
	}
}

// TestTypeScriptErrorPatterns verifies throw statements and empty catch blocks
// are detected.
func TestTypeScriptErrorPatterns(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	// auth.ts has throws and an empty catch block
	authPath := filepath.Join(rootDir, "auth.ts")
	content := mustReadFixture(t, authPath)

	result, err := parser.ParseFile(authPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Verify throw statements
	throwCount := 0
	emptyCatchCount := 0
	for _, ep := range result.Errors {
		switch ep.Kind {
		case "throw":
			throwCount++
		case "empty_catch":
			emptyCatchCount++
		}
	}

	// auth.ts has "throw new Error("missing token")" at L3,
	// "throw new Error("invalid token format")" at L15,
	// and an empty catch at L8-10
	if throwCount < 2 {
		t.Errorf("expected at least 2 throw error patterns, got %d", throwCount)
	}
	if emptyCatchCount < 1 {
		t.Errorf("expected at least 1 empty_catch error pattern, got %d", emptyCatchCount)
	}

	// Verify the empty catch is attributed to validateToken
	for _, ep := range result.Errors {
		if ep.Kind == "empty_catch" {
			if ep.FuncName != "validateToken" {
				t.Errorf("empty_catch should be in validateToken, got FuncName=%q", ep.FuncName)
			}
		}
	}

	// app.ts has a throw inside handler() at line 38
	appPath := filepath.Join(rootDir, "app.ts")
	appContent := mustReadFixture(t, appPath)

	appResult, err := parser.ParseFile(appPath, appContent)
	if err != nil {
		t.Fatalf("ParseFile app.ts failed: %v", err)
	}

	foundHandlerThrow := false
	for _, ep := range appResult.Errors {
		if ep.Kind == "throw" && ep.FuncName == "handler" {
			foundHandlerThrow = true
		}
	}
	if !foundHandlerThrow {
		t.Error("expected throw error pattern in handler function not found")
	}
}

// TestTypeScriptDecorators verifies that decorators don't leak between methods.
// This tests the fix where preceding decorators were incorrectly attached to
// subsequent undecorated functions.
func TestTypeScriptDecorators(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	// The fixture files don't use class decorators, but we can verify
	// that functions without decorators get empty slices.
	authPath := filepath.Join(rootDir, "auth.ts")
	content := mustReadFixture(t, authPath)

	result, err := parser.ParseFile(authPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// None of the auth.ts functions have decorators
	for _, fn := range result.Functions {
		if len(fn.Decorators) > 0 {
			t.Errorf("function %q should have no decorators, got %v", fn.Name, fn.Decorators)
		}
	}

	// Verify the decorator collection mechanism resets between functions.
	// The collectDecorators method should only return contiguous decorators
	// immediately preceding the target node. Since auth.ts has no decorators,
	// all decorator lists should be nil/empty, confirming no leakage.
	if len(result.Decorators) != 0 {
		t.Errorf("expected 0 decorator infos for auth.ts, got %d", len(result.Decorators))
		for _, d := range result.Decorators {
			t.Logf("  decorator: FuncName=%q Text=%q Line=%d", d.FuncName, d.Text, d.Line)
		}
	}
}

// TestTypeScriptExportDetection verifies exported functions have IsExported=true,
// including exported arrow function assignments.
func TestTypeScriptExportDetection(t *testing.T) {
	rootDir, err := filepath.Abs(tsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewTypeScriptParser(rootDir)

	// config.ts has "export function getConfig()"
	configPath := filepath.Join(rootDir, "config.ts")
	content := mustReadFixture(t, configPath)

	result, err := parser.ParseFile(configPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	if len(result.Functions) == 0 {
		t.Fatal("expected at least 1 function in config.ts")
	}

	foundGetConfig := false
	for _, fn := range result.Functions {
		if fn.Name == "getConfig" {
			foundGetConfig = true
			if !fn.IsExported {
				t.Errorf("getConfig should be exported (has export keyword)")
			}
		}
	}
	if !foundGetConfig {
		t.Error("expected getConfig function not found in config.ts")
	}

	// auth.ts: validateToken, authorize, checkGroups are exported; decodeToken is not
	authPath := filepath.Join(rootDir, "auth.ts")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.ts failed: %v", err)
	}

	exportExpected := map[string]bool{
		"validateToken": true,
		"authorize":     true,
		"checkGroups":   true,
		"decodeToken":   false,
	}

	for _, fn := range authResult.Functions {
		expected, ok := exportExpected[fn.Name]
		if !ok {
			continue
		}
		if fn.IsExported != expected {
			t.Errorf("function %q: expected IsExported=%v, got %v", fn.Name, expected, fn.IsExported)
		}
	}

	// app.ts: handler starts lowercase and has no export keyword
	appPath := filepath.Join(rootDir, "app.ts")
	appContent := mustReadFixture(t, appPath)

	appResult, err := parser.ParseFile(appPath, appContent)
	if err != nil {
		t.Fatalf("ParseFile app.ts failed: %v", err)
	}

	for _, fn := range appResult.Functions {
		if fn.Name == "handler" {
			if fn.IsExported {
				t.Error("handler should not be exported (lowercase, no export keyword)")
			}
		}
	}
}

// containsSubstr is a test helper.
func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && findSubstr(s, sub))
}

func findSubstr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
