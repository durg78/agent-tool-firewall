package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestNewHandler_ValidConfig(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory
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

	handler, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	if handler == nil {
		t.Error("Expected non-nil handler")
	}
}

func TestNewHandler_MissingConfig(t *testing.T) {
	// Create temp dir with no config
	tmpDir := t.TempDir()

	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	_, err := NewHandler()
	if err == nil {
		t.Error("Expected error for missing config, got nil")
	}
}

func TestHandler_ServeHTTP_GET(t *testing.T) {
	// Create a test backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Backend response"))
	}))
	defer backend.Close()

	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory
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
	err = os.WriteFile(rulesPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	handler, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create test request to backend
	req := httptest.NewRequest("GET", backend.URL, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Response should include the safety prefix
	if !bytes.Contains(body, []byte("[UNTRUSTED EXTERNAL DATA")) {
		t.Errorf("Expected safety prefix in response, got %q", string(body))
	}
}

func TestHandler_ServeHTTP_BadGateway(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory
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
	err = os.WriteFile(rulesPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	handler, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create request to non-existent backend
	req := httptest.NewRequest("GET", "http://localhost:1", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502, got %d", resp.StatusCode)
	}
}

func TestHandler_ServeHTTP_Sanitization(t *testing.T) {
	// Create a test backend that returns HTML with scripts
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body><script>alert('xss')</script><h1>Safe</h1></body></html>"))
	}))
	defer backend.Close()

	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory
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
	err = os.WriteFile(rulesPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	handler, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// Create test request
	req := httptest.NewRequest("GET", backend.URL, nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Script tags should be sanitized
	if bytes.Contains(body, []byte("<script>")) {
		t.Errorf("Expected <script> to be sanitized, got %q", string(body))
	}

	// Safe tags should remain
	if !bytes.Contains(body, []byte("<h1>")) {
		t.Errorf("Expected <h1> to be preserved, got %q", string(body))
	}
}

func TestHandler_HandleCONNECT(t *testing.T) {
	// Create temporary config and rules files
	tmpDir := t.TempDir()

	// Create config directory
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
	err = os.WriteFile(rulesPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to write rules: %v", err)
	}

	// Temporarily change working directory
	origWd, _ := os.Getwd()
	os.Chdir(tmpDir)
	defer os.Chdir(origWd)

	handler, err := NewHandler()
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	// CONNECT to non-existent server should fail
	req := httptest.NewRequest("CONNECT", "http://localhost:1", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("Expected status 502 for failed CONNECT, got %d", resp.StatusCode)
	}
}
