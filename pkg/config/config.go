package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds user-defined rules loaded from a YAML config file.
type Config struct {
	PlatformKnowledge []CustomFieldSemantics `yaml:"platform_knowledge"`
	AuthPatterns      []CustomAuthPattern    `yaml:"auth_patterns"`
	EntryPoints       []CustomEntryPoint     `yaml:"entry_points"`
	SecurityFields    []string               `yaml:"security_fields"`
	SkipDirs          []string               `yaml:"skip_dirs"`
}

// CustomFieldSemantics defines platform-specific meaning for a config field.
type CustomFieldSemantics struct {
	Field          string `yaml:"field"`
	EmptyMeaning   string `yaml:"empty_meaning"`
	Permissiveness string `yaml:"permissiveness"` // PERMISSIVE, RESTRICTIVE, NEUTRAL
}

// CustomAuthPattern defines a custom authentication/authorization function pattern.
type CustomAuthPattern struct {
	Name string `yaml:"name"`
	Kind string `yaml:"kind"` // authn, authz, validator, session
}

// CustomEntryPoint defines a custom entry point detection rule.
type CustomEntryPoint struct {
	Decorator string `yaml:"decorator"`
	FuncName  string `yaml:"func_name"`
}

// LoadConfig reads and parses a YAML config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config YAML: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

// validate checks that the config has valid values.
func (c *Config) validate() error {
	validPermissiveness := map[string]bool{
		"PERMISSIVE":  true,
		"RESTRICTIVE": true,
		"NEUTRAL":     true,
	}

	for i, pk := range c.PlatformKnowledge {
		if pk.Field == "" {
			return fmt.Errorf("platform_knowledge[%d]: field is required", i)
		}
		if pk.Permissiveness != "" && !validPermissiveness[pk.Permissiveness] {
			return fmt.Errorf("platform_knowledge[%d]: permissiveness must be PERMISSIVE, RESTRICTIVE, or NEUTRAL, got %q", i, pk.Permissiveness)
		}
	}

	validKinds := map[string]bool{
		"authn":     true,
		"authz":     true,
		"validator": true,
		"session":   true,
	}

	for i, ap := range c.AuthPatterns {
		if ap.Name == "" {
			return fmt.Errorf("auth_patterns[%d]: name is required", i)
		}
		if ap.Kind != "" && !validKinds[ap.Kind] {
			return fmt.Errorf("auth_patterns[%d]: kind must be authn, authz, validator, or session, got %q", i, ap.Kind)
		}
	}

	for i, ep := range c.EntryPoints {
		if ep.Decorator == "" && ep.FuncName == "" {
			return fmt.Errorf("entry_points[%d]: at least one of decorator or func_name is required", i)
		}
	}

	return nil
}
