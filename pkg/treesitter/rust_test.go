package treesitter

import (
	"path/filepath"
	"testing"
)

const rustFixtureDir = "../../testdata/rust-basic"

// TestRustParserBasic parses main.rs and auth.rs, verifies function and call site counts.
func TestRustParserBasic(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	// Parse main.rs
	mainPath := filepath.Join(rootDir, "src", "main.rs")
	mainContent := mustReadFixture(t, mainPath)

	mainResult, err := parser.ParseFile(mainPath, mainContent)
	if err != nil {
		t.Fatalf("ParseFile main.rs failed: %v", err)
	}

	// main.rs defines: get_data, admin_dashboard, health, main
	if len(mainResult.Functions) < 4 {
		t.Errorf("main.rs: expected at least 4 functions, got %d", len(mainResult.Functions))
		for i, fn := range mainResult.Functions {
			t.Logf("  fn[%d]: Name=%q ID=%q Line=%d", i, fn.Name, fn.ID, fn.Line)
		}
	}

	// main.rs has calls to: validate_token, get_config, authorize, json, headers, get,
	// HttpResponse::*, HttpServer::new, App::new, unwrap, service (x3), bind, run, await, etc.
	if len(mainResult.CallSites) < 5 {
		t.Errorf("main.rs: expected at least 5 call sites, got %d", len(mainResult.CallSites))
		for i, cs := range mainResult.CallSites {
			t.Logf("  cs[%d]: Callee=%q Line=%d Caller=%q", i, cs.CalleeName, cs.Line, cs.CallerFuncID)
		}
	}

	// Parse auth.rs
	authPath := filepath.Join(rootDir, "src", "auth.rs")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.rs failed: %v", err)
	}

	// auth.rs defines: validate_token, decode_token, authorize, check_groups
	if len(authResult.Functions) < 4 {
		t.Errorf("auth.rs: expected at least 4 functions, got %d", len(authResult.Functions))
		for i, fn := range authResult.Functions {
			t.Logf("  fn[%d]: Name=%q ID=%q Line=%d", i, fn.Name, fn.ID, fn.Line)
		}
	}

	// auth.rs has internal calls: ok_or, decode_token, starts_with, is_empty, iter, any, contains, etc.
	if len(authResult.CallSites) < 3 {
		t.Errorf("auth.rs: expected at least 3 call sites, got %d", len(authResult.CallSites))
	}
}

// TestRustFunctionExtraction verifies that specific functions are extracted with
// correct names, line numbers, and visibility.
func TestRustFunctionExtraction(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	// main.rs functions
	mainPath := filepath.Join(rootDir, "src", "main.rs")
	mainContent := mustReadFixture(t, mainPath)

	mainResult, err := parser.ParseFile(mainPath, mainContent)
	if err != nil {
		t.Fatalf("ParseFile main.rs failed: %v", err)
	}

	mainExpected := map[string]struct {
		line       int
		isExported bool
	}{
		"get_data":        {line: 10, isExported: false},
		"admin_dashboard": {line: 26, isExported: false},
		"health":          {line: 34, isExported: false},
		"main":            {line: 39, isExported: false},
	}

	mainFound := map[string]bool{}
	for _, fn := range mainResult.Functions {
		exp, ok := mainExpected[fn.Name]
		if !ok {
			continue
		}
		mainFound[fn.Name] = true

		if fn.Line != exp.line {
			t.Errorf("main.rs function %q: expected line %d, got %d", fn.Name, exp.line, fn.Line)
		}
		if fn.IsExported != exp.isExported {
			t.Errorf("main.rs function %q: expected IsExported=%v, got %v", fn.Name, exp.isExported, fn.IsExported)
		}
	}

	for name := range mainExpected {
		if !mainFound[name] {
			t.Errorf("expected function %q not found in main.rs", name)
		}
	}

	// auth.rs functions
	authPath := filepath.Join(rootDir, "src", "auth.rs")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.rs failed: %v", err)
	}

	authExpected := map[string]struct {
		line       int
		isExported bool
	}{
		"validate_token": {line: 8, isExported: true},
		"decode_token":   {line: 14, isExported: false},
		"authorize":      {line: 24, isExported: true},
		"check_groups":   {line: 31, isExported: true},
	}

	authFound := map[string]bool{}
	for _, fn := range authResult.Functions {
		exp, ok := authExpected[fn.Name]
		if !ok {
			continue
		}
		authFound[fn.Name] = true

		if fn.Line != exp.line {
			t.Errorf("auth.rs function %q: expected line %d, got %d", fn.Name, exp.line, fn.Line)
		}
		if fn.IsExported != exp.isExported {
			t.Errorf("auth.rs function %q: expected IsExported=%v, got %v", fn.Name, exp.isExported, fn.IsExported)
		}
	}

	for name := range authExpected {
		if !authFound[name] {
			t.Errorf("expected function %q not found in auth.rs", name)
		}
	}
}

// TestRustAttributes verifies that #[get("/api/data")] is on get_data only
// and NOT leaked to admin_dashboard (the contiguous-reset bug we fixed).
func TestRustAttributes(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	mainPath := filepath.Join(rootDir, "src", "main.rs")
	content := mustReadFixture(t, mainPath)

	result, err := parser.ParseFile(mainPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// Each function should have exactly its own attribute, not attributes from prior functions.
	attrExpected := map[string]struct {
		attrCount int
		contains  string
	}{
		"get_data":        {attrCount: 1, contains: `#[get("/api/data")]`},
		"admin_dashboard": {attrCount: 1, contains: `#[get("/admin/dashboard")]`},
		"health":          {attrCount: 1, contains: `#[get("/health")]`},
		"main":            {attrCount: 1, contains: `#[actix_web::main]`},
	}

	for _, fn := range result.Functions {
		exp, ok := attrExpected[fn.Name]
		if !ok {
			continue
		}

		if len(fn.Decorators) != exp.attrCount {
			t.Errorf("function %q: expected %d attribute(s), got %d: %v",
				fn.Name, exp.attrCount, len(fn.Decorators), fn.Decorators)
			continue
		}

		if exp.contains != "" {
			found := false
			for _, d := range fn.Decorators {
				if d == exp.contains {
					found = true
				}
			}
			if !found {
				t.Errorf("function %q: expected attribute %q, got %v", fn.Name, exp.contains, fn.Decorators)
			}
		}
	}

	// Verify decorator info entries match functions
	for _, d := range result.Decorators {
		if d.FuncName == "admin_dashboard" {
			if containsSubstr(d.Text, "/api/data") {
				t.Errorf("admin_dashboard has leaked decorator from get_data: %q", d.Text)
			}
		}
		if d.FuncName == "health" {
			if containsSubstr(d.Text, "/admin/dashboard") {
				t.Errorf("health has leaked decorator from admin_dashboard: %q", d.Text)
			}
		}
	}
}

// TestRustCallSiteExtraction verifies cross-file call detection. Since each file
// is parsed independently, we verify the CalleeName and CallerFuncID are correct
// within each file.
func TestRustCallSiteExtraction(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	mainPath := filepath.Join(rootDir, "src", "main.rs")
	content := mustReadFixture(t, mainPath)

	result, err := parser.ParseFile(mainPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	// get_data calls validate_token (L12) and authorize (L18) and get_config (L17)
	type expectedCall struct {
		calleeName string
		callerName string // just the function name portion of CallerFuncID
		line       int
	}

	expectedCalls := []expectedCall{
		{calleeName: "validate_token", callerName: "get_data", line: 12},
		{calleeName: "get_config", callerName: "get_data", line: 17},
		{calleeName: "authorize", callerName: "get_data", line: 18},
		{calleeName: "validate_token", callerName: "admin_dashboard", line: 28},
	}

	for _, ec := range expectedCalls {
		found := false
		for _, cs := range result.CallSites {
			if cs.CalleeName == ec.calleeName && cs.Line == ec.line {
				found = true
				// CallerFuncID should end with the expected function name
				if !hasSuffix(cs.CallerFuncID, ec.callerName) {
					t.Errorf("call to %q at line %d: expected CallerFuncID ending with %q, got %q",
						ec.calleeName, ec.line, ec.callerName, cs.CallerFuncID)
				}
				break
			}
		}
		if !found {
			t.Errorf("expected call to %q at line %d not found", ec.calleeName, ec.line)
		}
	}

	// Parse auth.rs: decode_token is called inside validate_token
	authPath := filepath.Join(rootDir, "src", "auth.rs")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.rs failed: %v", err)
	}

	foundDecodeToken := false
	for _, cs := range authResult.CallSites {
		if cs.CalleeName == "decode_token" {
			foundDecodeToken = true
			if !hasSuffix(cs.CallerFuncID, "validate_token") {
				t.Errorf("decode_token call: expected CallerFuncID ending with validate_token, got %q", cs.CallerFuncID)
			}
		}
	}
	if !foundDecodeToken {
		t.Error("expected decode_token call in auth.rs not found")
	}
}

// TestRustUnwrapDetection verifies .unwrap() calls produce ErrorPattern entries.
func TestRustUnwrapDetection(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	// main.rs line 28: validate_token(token).unwrap()
	mainPath := filepath.Join(rootDir, "src", "main.rs")
	content := mustReadFixture(t, mainPath)

	result, err := parser.ParseFile(mainPath, content)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	unwrapCount := 0
	for _, ep := range result.Errors {
		if ep.Kind == "unwrap" {
			unwrapCount++
			if ep.FuncName != "admin_dashboard" {
				t.Errorf("unwrap error: expected FuncName=admin_dashboard, got %q", ep.FuncName)
			}
			if ep.File != mainPath {
				t.Errorf("unwrap error: expected File=%q, got %q", mainPath, ep.File)
			}
		}
	}

	if unwrapCount < 1 {
		t.Errorf("expected at least 1 unwrap error pattern in main.rs, got %d", unwrapCount)
		t.Log("All errors found:")
		for i, ep := range result.Errors {
			t.Logf("  err[%d]: Kind=%q FuncName=%q Line=%d Message=%q", i, ep.Kind, ep.FuncName, ep.Line, ep.Message)
		}
	}

	// config.rs has unwrap_or_else calls, but those are not .unwrap() and should NOT
	// be flagged as unwrap error patterns
	configPath := filepath.Join(rootDir, "src", "config.rs")
	configContent := mustReadFixture(t, configPath)

	configResult, err := parser.ParseFile(configPath, configContent)
	if err != nil {
		t.Fatalf("ParseFile config.rs failed: %v", err)
	}

	for _, ep := range configResult.Errors {
		if ep.Kind == "unwrap" {
			t.Errorf("config.rs should not have unwrap errors (unwrap_or_else is safe), got: %q at line %d", ep.Message, ep.Line)
		}
	}
}

// TestRustImplMethods verifies methods inside impl blocks have correct TypeName.
// auth.rs does not use impl blocks (functions are standalone), but config.rs
// defines standalone functions too. We verify that functions outside impl blocks
// have empty TypeName.
func TestRustImplMethods(t *testing.T) {
	rootDir, err := filepath.Abs(rustFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	parser := NewRustParser(rootDir)

	// All functions in auth.rs are standalone (no impl block)
	authPath := filepath.Join(rootDir, "src", "auth.rs")
	authContent := mustReadFixture(t, authPath)

	authResult, err := parser.ParseFile(authPath, authContent)
	if err != nil {
		t.Fatalf("ParseFile auth.rs failed: %v", err)
	}

	for _, fn := range authResult.Functions {
		if fn.TypeName != "" {
			t.Errorf("auth.rs function %q: expected empty TypeName (no impl), got %q", fn.Name, fn.TypeName)
		}
		if fn.IsMethod {
			t.Errorf("auth.rs function %q: expected IsMethod=false, got true", fn.Name)
		}
	}

	// main.rs functions are also standalone
	mainPath := filepath.Join(rootDir, "src", "main.rs")
	mainContent := mustReadFixture(t, mainPath)

	mainResult, err := parser.ParseFile(mainPath, mainContent)
	if err != nil {
		t.Fatalf("ParseFile main.rs failed: %v", err)
	}

	for _, fn := range mainResult.Functions {
		if fn.TypeName != "" {
			t.Errorf("main.rs function %q: expected empty TypeName (no impl), got %q", fn.Name, fn.TypeName)
		}
		if fn.IsMethod {
			t.Errorf("main.rs function %q: expected IsMethod=false, got true", fn.Name)
		}
	}
}

// hasSuffix checks if s ends with suffix (using a dot separator or exact match).
func hasSuffix(s, suffix string) bool {
	if s == suffix {
		return true
	}
	dotSuffix := "." + suffix
	return len(s) >= len(dotSuffix) && s[len(s)-len(dotSuffix):] == dotSuffix
}
