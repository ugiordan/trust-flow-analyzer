package config

type Config struct {
	AllowedGroups []string
	EmailDomain   string
	Audiences     []string
}

func DefaultConfig() *Config {
	return &Config{
		AllowedGroups: nil,
		EmailDomain:   "",
		Audiences:     nil,
	}
}
