# Makefile for MiniWG - Minimal WireGuard Implementation
# 
# Targets:
#   build    - Build the miniwg binary
#   test     - Run all tests
#   clean    - Clean build artifacts
#   run      - Build and run miniwg
#   fmt      - Format Go code
#   vet      - Run go vet

.PHONY: all build test clean run fmt vet help

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

# Run all quality checks
check: fmt vet test

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
	@echo "  check         - Run fmt, vet, and test"
	@echo "  help          - Show this help message"