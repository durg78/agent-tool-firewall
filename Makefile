.PHONY: test test-verbose test-coverage build clean help

# Default target
help:
	@echo "Available targets:"
	@echo "  test          - Run all tests"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  build         - Build the main application"
	@echo "  clean         - Clean build artifacts"

# Run all tests
test:
	@go test ./...
	@echo "Running end-to-end tests..."
	@bash ./run_tests.sh

# Run tests with verbose output
test-verbose:
	@go test -v -race ./...

# Run tests with coverage
test-coverage:
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Build the application
build:
	@go build -trimpath -ldflags="-s -w" -o bin/atf-proxy ./cmd/atf-proxy

# Clean build artifacts
clean:
	@rm -rf bin/
	@rm -f coverage.out coverage.html
	@rm -rf logs/
