package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port          int    `yaml:"port"`
	MaxBodySizeMB int    `yaml:"max_body_size_mb"`

	Logging struct {
		Enabled     bool   `yaml:"enabled"`
		Format      string `yaml:"format"`
		Destination string `yaml:"destination"`
		Rotation    struct {
			MaxSizeMB   int `yaml:"max_size_mb"`
			MaxBackups  int `yaml:"max_backups"`
			MaxAgeDays  int `yaml:"max_age_days"`
			Compress    bool `yaml:"compress"`
		} `yaml:"rotation"`
	} `yaml:"logging"`

	Coraza CorazaConfig `yaml:"coraza"`

	// Prompt injection settings
	PromptInjectionThreshold int `yaml:"prompt_injection_threshold"`

	// Security settings
	RequestTimeoutSeconds    int  `yaml:"request_timeout_seconds"`
	ResponseTimeoutSeconds   int  `yaml:"response_timeout_seconds"`
	RateLimitPerMinute       int  `yaml:"rate_limit_per_minute"`
	EnableDebugLogging       bool `yaml:"enable_debug_logging"`
	SanitizeErrorMessages    bool `yaml:"sanitize_error_messages"`

	// Request protection settings (outbound from agent perspective)
	RequestProtection struct {
		Enabled     bool                      `yaml:"enabled"`
		Whitelist   []RequestWhitelistEntry   `yaml:"whitelist"`
	} `yaml:"request_protection"`
}

// CorazaConfig holds WAF-specific settings
type CorazaConfig struct {
	RulesFile string `yaml:"rules_file"`
}

// RequestWhitelistEntry defines a whitelisted destination for outgoing requests
type RequestWhitelistEntry struct {
	URLPattern     string  `yaml:"url_pattern"`
	AllowedRuleIDs []int   `yaml:"allowed_rule_ids"`
	Description   string   `yaml:"description"`
}

func Load() (*Config, error) {
	data, err := os.ReadFile("config/config.yaml")
	if err != nil {
		return nil, err
	}

	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}

	// Sensible defaults
	if c.Port == 0 {
		c.Port = 3123
	}
	if c.PromptInjectionThreshold == 0 {
		c.PromptInjectionThreshold = 7
	}
	if c.MaxBodySizeMB == 0 {
		c.MaxBodySizeMB = 8
	}

	// Security defaults
	if c.RequestTimeoutSeconds == 0 {
		c.RequestTimeoutSeconds = 30
	}
	if c.ResponseTimeoutSeconds == 0 {
		c.ResponseTimeoutSeconds = 30
	}
	if c.RateLimitPerMinute == 0 {
		c.RateLimitPerMinute = 60
	}

	// Logging rotation defaults
	if c.Logging.Rotation.MaxSizeMB == 0 {
		c.Logging.Rotation.MaxSizeMB = 100
	}
	if c.Logging.Rotation.MaxBackups == 0 {
		c.Logging.Rotation.MaxBackups = 5
	}
	if c.Logging.Rotation.MaxAgeDays == 0 {
		c.Logging.Rotation.MaxAgeDays = 30
	}
	if !c.Logging.Rotation.Compress {
		c.Logging.Rotation.Compress = true
	}

	return &c, nil
}
