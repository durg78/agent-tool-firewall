package coraza

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/durg78/agent-tool-firewall/internal/config"
)

func TestNew_WAFCreation(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory and file
	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	// Create logs directory
	logDir := filepath.Join(tmpDir, "logs")
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	configContent := `
port: 3123
max_body_size_mb: 8
workers: 2

logging:
  enabled: true
  format: json
  destination: ` + filepath.Join(tmpDir, "logs", "atf.log") + `

coraza:
  response_only: false
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `

prompt_injection_threshold: 7
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Create minimal rules file
	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	rulesContent := `
# Minimal rules for testing
SecRule REQUEST_URI "@streq /test" "id:1,phase:1,deny,status:403"
`
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	// Load config
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	// Create WAF
	waf, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if waf == nil {
		t.Error("Expected non-nil WAF instance")
	}
}

func TestNew_WAFWithMissingRules(t *testing.T) {
	// Create temporary config with non-existent rules file
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	// Create logs directory
	logDir := filepath.Join(tmpDir, "logs")
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	configContent := `
port: 3123
logging:
  enabled: true
  format: json
  destination: ` + filepath.Join(tmpDir, "logs", "atf.log") + `
coraza:
  response_only: false
  rules_file: /nonexistent/rules.yaml
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	_, err = New(cfg)
	if err == nil {
		t.Error("Expected error for missing rules file, got nil")
	}
}

func TestProcessResponseBody_SafeContent(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	// Create logs directory
	logDir := filepath.Join(tmpDir, "logs")
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	configContent := `
port: 3123
logging:
  enabled: true
  format: json
  destination: ` + filepath.Join(tmpDir, "logs", "atf.log") + `
coraza:
  response_only: false
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	rulesContent := `
# Empty rules for testing
`
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	waf, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with safe content
	safeBody := []byte("<html><body><h1>Safe content</h1></body></html>")
	blocked, msg, err := waf.ProcessResponseBody(safeBody)

	if err != nil {
		t.Errorf("ProcessResponseBody() error = %v", err)
	}
	if blocked {
		t.Errorf("Expected safe content not to be blocked, got blocked=true, msg=%q", msg)
	}
}

func TestProcessResponseBody_EmptyBody(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	// Create logs directory
	logDir := filepath.Join(tmpDir, "logs")
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	configContent := `
port: 3123
logging:
  enabled: true
  format: json
  destination: ` + filepath.Join(tmpDir, "logs", "atf.log") + `
coraza:
  response_only: false
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	rulesContent := ""
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	waf, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with empty body
	blocked, msg, err := waf.ProcessResponseBody([]byte{})

	if err != nil {
		t.Errorf("ProcessResponseBody() error = %v", err)
	}
	if blocked {
		t.Errorf("Expected empty body not to be blocked, got blocked=true, msg=%q", msg)
	}
}

func TestProcessResponseBody_LargeBody(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
	// Create logs directory
	logDir := filepath.Join(tmpDir, "logs")
	err = os.MkdirAll(logDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create logs dir: %v", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	configContent := `
port: 3123
logging:
  enabled: true
  format: json
  destination: ` + filepath.Join(tmpDir, "logs", "atf.log") + `
coraza:
  response_only: false
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
`
	err = os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	rulesPath := filepath.Join(tmpDir, "rules.yaml")
	rulesContent := ""
	err = os.WriteFile(rulesPath, []byte(rulesContent), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}

	waf, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Test with large body
	largeBody := make([]byte, 1024*1024) // 1MB
	blocked, msg, err := waf.ProcessResponseBody(largeBody)

	if err != nil {
		t.Errorf("ProcessResponseBody() error = %v", err)
	}
	if blocked {
		t.Errorf("Expected large body not to be blocked, got blocked=true, msg=%q", msg)
	}
}
