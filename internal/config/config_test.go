package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	// Create a temporary directory with config subdirectory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")

	configContent := `
port: 8080
max_body_size_mb: 16
workers: 4

logging:
  enabled: true
  format: json
  destination: logs/atf.log

coraza:
  rules_file: rules/custom.rules

prompt_injection_threshold: 8
`

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Port != 8080 {
		t.Errorf("Expected Port 8080, got %d", cfg.Port)
	}
	if cfg.MaxBodySizeMB != 16 {
		t.Errorf("Expected MaxBodySizeMB 16, got %d", cfg.MaxBodySizeMB)
	}
	if cfg.Logging.Enabled != true {
		t.Errorf("Expected Logging.Enabled true, got %v", cfg.Logging.Enabled)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("Expected Logging.Format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.PromptInjectionThreshold != 8 {
		t.Errorf("Expected PromptInjectionThreshold 8, got %d", cfg.PromptInjectionThreshold)
	}
}

func TestLoad_Defaults(t *testing.T) {
	// Create a temporary directory with config subdirectory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")

	configContent := `
# Minimal config - should use defaults
port: 0
max_body_size_mb: 0
workers: 0
prompt_injection_threshold: 0

logging:
  enabled: false
  format: ""
  destination: ""

coraza:
  rules_file: ""
`

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check defaults
	if cfg.Port != 3123 {
		t.Errorf("Expected default Port 3123, got %d", cfg.Port)
	}
	if cfg.MaxBodySizeMB != 8 {
		t.Errorf("Expected default MaxBodySizeMB 8, got %d", cfg.MaxBodySizeMB)
	}
	if cfg.PromptInjectionThreshold != 7 {
		t.Errorf("Expected default PromptInjectionThreshold 7, got %d", cfg.PromptInjectionThreshold)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	// Temporarily change to a directory with no config
	tmpDir := t.TempDir()

	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	_, err := Load()
	if err == nil {
		t.Error("Expected error when config file is missing, got nil")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Create a temporary directory with config subdirectory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")

	configContent := `
port: invalid_yaml_{{{
  broken: [
`

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	_, err = Load()
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestLoad_NonNumericPort(t *testing.T) {
	// Create a temporary directory with config subdirectory
	tmpDir := t.TempDir()
	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")

	configContent := `
port: abc
`

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp config: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	_, err = Load()
	if err == nil {
		t.Error("Expected error for non-numeric port, got nil")
	}
	// YAML validation should fail for non-numeric port
	if !strings.Contains(err.Error(), "cannot unmarshal") {
		t.Errorf("Expected YAML unmarshal error, got: %v", err)
	}
}
