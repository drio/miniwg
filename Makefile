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

.PHONY: all build test clean run fmt vet security gosec vulncheck help

# Default target
all: build

# Build the miniwg binary
build:
	@echo "Building miniwg..."
	go build -o miniwg .

# Run all tests with verbose output
test:
	@echo "Running tests..."
	go test -v .

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -cover .

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
	go fmt .

# Run go vet for static analysis
vet:
	@echo "Running go vet..."
	go vet .

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
check: fmt vet test security

# Show available targets
help:
	@echo "Available targets:"
	@echo "  build         - Build the miniwg binary"
	@echo "  test          - Run all tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean         - Clean build artifacts"
	@echo "  run           - Build and run miniwg"
	@echo "  fmt           - Format Go code"
	@echo "  vet           - Run go vet"
	@echo "  gosec         - Run gosec security scanner"
	@echo "  vulncheck     - Run vulnerability scanner"
	@echo "  security      - Run all security checks"
	@echo "  check         - Run fmt, vet, test, and security"
	@echo "  help          - Show this help message"