package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Port          int    `yaml:"port"`
	MaxBodySizeMB int    `yaml:"max_body_size_mb"`
	Workers       int    `yaml:"workers"`

	Logging struct {
		Enabled     bool   `yaml:"enabled"`
		Format      string `yaml:"format"`
		Destination string `yaml:"destination"`
	} `yaml:"logging"`

	Coraza struct {
		ResponseOnly bool   `yaml:"response_only"`
		RulesFile    string `yaml:"rules_file"`
	} `yaml:"coraza"`

	// Prompt injection settings
	PromptInjectionThreshold int `yaml:"prompt_injection_threshold"`
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

	return &c, nil
}
