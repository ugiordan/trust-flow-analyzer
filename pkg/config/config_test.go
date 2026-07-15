package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigValid(t *testing.T) {
	content := `
platform_knowledge:
  - field: "MyCustomField"
    empty_meaning: "Custom security gate disabled"
    permissiveness: "PERMISSIVE"

auth_patterns:
  - name: "custom_authenticate"
    kind: "authn"
  - name: "check_authorization"
    kind: "authz"

entry_points:
  - decorator: "@my_app.route"
  - func_name: "custom_handler"

security_fields:
  - "MyAuthProxy"
  - "CustomTLS"

skip_dirs:
  - "legacy"
  - "deprecated"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.PlatformKnowledge) != 1 {
		t.Errorf("expected 1 platform_knowledge entry, got %d", len(cfg.PlatformKnowledge))
	}
	if cfg.PlatformKnowledge[0].Field != "MyCustomField" {
		t.Errorf("expected field MyCustomField, got %q", cfg.PlatformKnowledge[0].Field)
	}

	if len(cfg.AuthPatterns) != 2 {
		t.Errorf("expected 2 auth_patterns, got %d", len(cfg.AuthPatterns))
	}

	if len(cfg.EntryPoints) != 2 {
		t.Errorf("expected 2 entry_points, got %d", len(cfg.EntryPoints))
	}

	if len(cfg.SecurityFields) != 2 {
		t.Errorf("expected 2 security_fields, got %d", len(cfg.SecurityFields))
	}

	if len(cfg.SkipDirs) != 2 {
		t.Errorf("expected 2 skip_dirs, got %d", len(cfg.SkipDirs))
	}
}

func TestLoadConfigInvalidPermissiveness(t *testing.T) {
	content := `
platform_knowledge:
  - field: "test"
    permissiveness: "INVALID"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid permissiveness")
	}
}

func TestLoadConfigInvalidKind(t *testing.T) {
	content := `
auth_patterns:
  - name: "test_func"
    kind: "invalid"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
}

func TestLoadConfigMissingField(t *testing.T) {
	content := `
platform_knowledge:
  - empty_meaning: "test"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestLoadConfigEmptyEntryPoint(t *testing.T) {
	content := `
entry_points:
  - decorator: ""
    func_name: ""
`
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for entry point with no decorator or func_name")
	}
}

func TestLoadConfigFileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfigEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("empty config should be valid: %v", err)
	}
	if len(cfg.PlatformKnowledge) != 0 {
		t.Error("expected empty platform_knowledge")
	}
}
