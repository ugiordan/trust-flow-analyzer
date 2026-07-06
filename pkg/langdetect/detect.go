package langdetect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DetectLanguage determines the primary language of a project by checking
// for language-specific marker files. Priority: go > python > typescript > rust.
func DetectLanguage(dir string) (string, error) {
	markers := []struct {
		file string
		lang string
	}{
		{"go.mod", "go"},
		{"pyproject.toml", "python"},
		{"setup.py", "python"},
		{"setup.cfg", "python"},
		{"package.json", "typescript"},
		{"tsconfig.json", "typescript"},
		{"Cargo.toml", "rust"},
	}

	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m.file)); err == nil {
			return m.lang, nil
		}
	}

	return "", fmt.Errorf("cannot detect language: no go.mod, pyproject.toml, package.json, or Cargo.toml found in %s", dir)
}

// DetectProjectName extracts the project/module name from the appropriate
// config file for the detected language.
func DetectProjectName(dir string, lang string) string {
	switch lang {
	case "go":
		return readGoModulePath(dir)
	case "python":
		return readPythonProjectName(dir)
	case "typescript":
		return readPackageJSONName(dir)
	case "rust":
		return readCargoName(dir)
	default:
		return filepath.Base(dir)
	}
}

func readGoModulePath(dir string) string {
	f, err := os.Open(filepath.Join(dir, "go.mod"))
	if err != nil {
		return filepath.Base(dir)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			mod := strings.TrimSpace(strings.TrimPrefix(line, "module"))
			if idx := strings.Index(mod, "//"); idx >= 0 {
				mod = strings.TrimSpace(mod[:idx])
			}
			return mod
		}
	}
	return filepath.Base(dir)
}

func readPythonProjectName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "pyproject.toml"))
	if err != nil {
		return filepath.Base(dir)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, `"'`)
				if name != "" {
					return name
				}
			}
		}
	}
	return filepath.Base(dir)
}

func readPackageJSONName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "package.json"))
	if err != nil {
		return filepath.Base(dir)
	}
	var pkg struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &pkg); err == nil && pkg.Name != "" {
		return pkg.Name
	}
	return filepath.Base(dir)
}

func readCargoName(dir string) string {
	data, err := os.ReadFile(filepath.Join(dir, "Cargo.toml"))
	if err != nil {
		return filepath.Base(dir)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "name") && strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				name = strings.Trim(name, `"'`)
				if name != "" {
					return name
				}
			}
		}
	}
	return filepath.Base(dir)
}
