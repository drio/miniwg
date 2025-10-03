# Makefile for MiniWG - Minimal WireGuard Implementation
#
# Targets:
#   build    - Build the miniwg binary
#   test     - Run all tests
#   clean    - Clean build artifacts
#   run      - Build and run miniwg
#   fmt      - Format Go code
#   vet      - Run go vet
#   security - Run security scans on packages

.PHONY: all build test test-race clean run fmt vet lint security gosec vulncheck help learning install-lint-tools

# Default target
all: help

# Build the miniwg binary
build:
	@echo "Building miniwg..."
	go build -o miniwg .

# Run all tests with verbose output
test:
	@echo "Running unit tests..."
	go test -v ./device ./config ./conn ./tun
	@echo "Running integration tests..."
	go test -v ./test

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -cover ./device ./config ./conn ./tun
	go test -v -cover ./test

# Run tests with race detector
test-race:
	@echo "Running tests with race detector..."
	go test -race ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f miniwg
	go clean

# Build and run miniwg
run: build
	@echo "Running miniwg..."
	./miniwg

# Format Go code
fmt:
	@echo "Formatting code..."
	go fmt ./device ./config ./conn ./tun ./test .

# Run go vet for static analysis
vet:
	@echo "Running go vet..."
	go vet ./device ./config ./conn ./tun ./test .

# Install linting tools if needed
install-lint-tools:
	@echo "Installing linting tools..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)

# Run golangci-lint
lint: install-lint-tools
	@echo "Running golangci-lint..."
	golangci-lint run ./...

# Security scanning targets

# Install security tools if needed
install-security-tools:
	@echo "Installing security scanning tools..."
	@which govulncheck > /dev/null || (echo "Installing govulncheck..." && go install golang.org/x/vuln/cmd/govulncheck@latest)

# Run gosec security scanner
gosec:
	@echo "Running gosec security scanner..."
	./bin/gosec ./...

# Run vulnerability scanner
vulncheck: install-security-tools
	@echo "Running vulnerability scanner..."
	govulncheck ./...

# Run all security checks
security: gosec vulncheck
	@echo "Security scanning complete"

# Run all quality and security checks
check: fmt vet lint test test-race security

# Generate HTML documentation from markdown
learning:
	@echo "Generating HTML documentation..."
	@which pandoc > /dev/null || (echo "Error: pandoc not installed. Install with: apt-get install pandoc or brew install pandoc" && exit 1)
	pandoc docs/learning-handshake.md -o docs/learning-handshake.html \
		--standalone \
		--toc \
		--css=https://cdn.simplecss.org/simple.min.css
	@echo "Documentation generated: docs/learning-handshake.html"
	@echo "Open in browser: file://$(PWD)/docs/learning-handshake.html"

# Show available targets
help:
	@echo "Available targets:"
	@echo "  build         - Build the miniwg binary"
	@echo "  test          - Run all tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  test-race     - Run tests with race detector"
	@echo "  clean         - Clean build artifacts"
	@echo "  run           - Build and run miniwg"
	@echo "  fmt           - Format Go code"
	@echo "  vet           - Run go vet"
	@echo "  lint          - Run golangci-lint"
	@echo "  gosec         - Run gosec security scanner"
	@echo "  vulncheck     - Run vulnerability scanner"
	@echo "  security      - Run all security checks"
	@echo "  check         - Run fmt, vet, lint, test, test-race, and security"
	@echo "  learning      - Generate HTML from learning-handshake.md"
	@echo "  help          - Show this help message"
