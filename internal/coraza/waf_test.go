package coraza

import (
	"net/http"
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

func TestNew_RequestProtection(t *testing.T) {
	// Create temporary config with request protection enabled
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
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
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
request_protection:
  enabled: true
  whitelist:
    - url_pattern: "https://api.openai.com/*"
      allowed_rule_ids: [900001, 900003]
      description: "OpenAI API - allowed to send JWT and API keys"
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

	if !waf.IsRequestEnabled() {
		t.Error("Expected request protection to be enabled")
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
	blocked, msg, err := waf.ProcessResponseBody(safeBody, 200)

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
	blocked, msg, err := waf.ProcessResponseBody([]byte{}, 200)

	if err != nil {
		t.Errorf("ProcessResponseBody() error = %v", err)
	}
	if blocked {
		t.Errorf("Expected empty body not to be blocked, got blocked=true, msg=%q", msg)
	}
}

func TestProcessRequestHeaders_OutboundBlocked(t *testing.T) {
	// Create temporary config with outbound protection enabled
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
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
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
request_protection:
  enabled: true
  whitelist:
    - url_pattern: "https://api.trusted.com/*"
      allowed_rule_ids: [900001]
      description: "Trusted API"
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

	// Test with sensitive data to non-whitelisted destination
	// Note: With Coraza-based inspection, requests are only blocked by Coraza rules
	// The old Go pattern matching for sensitive data is deprecated
	req, _ := http.NewRequest("GET", "https://malicious.com/api", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	result := waf.ProcessRequestHeaders(req)

	// Request should be allowed (no Coraza block) since there's no matching rule
	// Non-whitelisted destinations without Coraza blocks are allowed
	if result.Blocked {
		t.Errorf("Expected request to be allowed (no Coraza rule violation), got blocked=true")
	}
	if !result.Allowed {
		t.Error("Expected request to be allowed")
	}
}

func TestProcessRequestHeaders_RequestAllowed(t *testing.T) {
	// Create temporary config with request protection enabled
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
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
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
request_protection:
  enabled: true
  whitelist:
    - url_pattern: "https://api.trusted.com/*"
      allowed_rule_ids: [900001]
      description: "Trusted API"
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

	// Test with sensitive data to whitelisted destination with allowed data type
	req, _ := http.NewRequest("GET", "https://api.trusted.com/api", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")

	result := waf.ProcessRequestHeaders(req)

	if result.Blocked {
		t.Errorf("Expected request to be allowed (whitelisted), got blocked=true")
	}
	if !result.Allowed {
		t.Error("Expected request to be allowed")
	}
}

func TestProcessRequestBody_SensitiveData(t *testing.T) {
	// Create temporary config with outbound protection enabled
	tmpDir := t.TempDir()

	configDir := filepath.Join(tmpDir, "config")
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create config dir: %v", err)
	}
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
  rules_file: ` + filepath.Join(tmpDir, "rules.yaml") + `
request_protection:
  enabled: true
  whitelist:
    - url_pattern: "^https://example\\.com/.*"
      allowed_rule_ids: [1]
      description: "Example"
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

// Test with sensitive data in body
	// Note: With Coraza-based inspection, bodies are only blocked by Coraza rules
	// The old Go pattern matching for sensitive data is deprecated
	req, _ := http.NewRequest("POST", "https://example.com/api", nil)
	req.Header.Set("Content-Type", "application/json")
	body := []byte(`{"api_key": "test-key"}`)

	result := waf.ProcessRequestBody(req, body)

	// Request should be allowed (no Coraza block) since there's no matching rule
	// No whitelist means request is allowed without Coraza blocks
	if result.Blocked {
		t.Errorf("Expected request to be allowed (no Coraza rule violation), got blocked=true")
	}
	if !result.Allowed {
		t.Error("Expected request to be allowed")
	}
}
