package loader

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadModulePath(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "basic")
	mod, err := readModulePath(dir)
	if err != nil {
		t.Fatalf("readModulePath failed: %v", err)
	}
	if mod != "example.com/basic" {
		t.Errorf("got module path %q, want %q", mod, "example.com/basic")
	}
}

func TestReadModulePathMissing(t *testing.T) {
	dir := t.TempDir()
	_, err := readModulePath(dir)
	if err == nil {
		t.Error("expected error for missing go.mod")
	}
}

func TestReadModulePathNoModule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("go 1.23\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readModulePath(dir)
	if err == nil {
		t.Error("expected error for go.mod without module directive")
	}
}

func TestLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "basic")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	prog, err := Load(absDir, os.Stderr)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if prog.ModulePath != "example.com/basic" {
		t.Errorf("ModulePath = %q, want %q", prog.ModulePath, "example.com/basic")
	}

	if prog.SSA == nil {
		t.Error("SSA program is nil")
	}

	if prog.CallGraph == nil {
		t.Error("CallGraph is nil")
	}

	if len(prog.Packages) == 0 {
		t.Error("no packages loaded")
	}
}

func TestIsModuleFunc(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "basic")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	prog, err := Load(absDir, os.Stderr)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	moduleCount := 0
	totalCount := 0
	for fn := range prog.CallGraph.Nodes {
		if fn == nil {
			continue
		}
		totalCount++
		if prog.IsModuleFunc(fn) {
			moduleCount++
		}
	}

	if moduleCount == 0 {
		t.Error("no module functions found")
	}
	if moduleCount >= totalCount {
		t.Errorf("module filtering not working: %d module funcs out of %d total", moduleCount, totalCount)
	}
}

func TestSortedModuleFunctions(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "basic")
	absDir, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}

	prog, err := Load(absDir, os.Stderr)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	fns := SortedModuleFunctions(prog)
	if len(fns) == 0 {
		t.Error("no sorted module functions returned")
	}

	for i := 1; i < len(fns); i++ {
		prev := fns[i-1].String()
		curr := fns[i].String()
		if prev > curr {
			t.Errorf("functions not sorted: %s > %s", prev, curr)
		}
	}
}
