# Variables
BINARY_NAME=sni-capture
BINARY_DIR=bin
GO=go
GOFLAGS=-ldflags="-s -w"

# Linux architectures to build for
LINUX_ARCHS=amd64 arm64 arm ppc64le s390x

# Default target
all: clean build

# Create binary directory and build
build:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)

# Build for all Linux architectures
linux: clean
	@mkdir -p $(BINARY_DIR)
	@for arch in $(LINUX_ARCHS); do \
		echo "Building for linux/$$arch..."; \
		GOOS=linux GOARCH=$$arch $(GO) build $(GOFLAGS) -o $(BINARY_DIR)/$(BINARY_NAME)-linux-$$arch; \
	done

# Clean build artifacts
clean:
	@rm -rf $(BINARY_DIR)

# Install dependencies
deps:
	$(GO) mod tidy

# Run the application
run: build
	./$(BINARY_DIR)/$(BINARY_NAME)

# Run tests
test:
	$(GO) test ./...

# Format code
fmt:
	$(GO) fmt ./...

# Install the binary
install: build
	cp $(BINARY_DIR)/$(BINARY_NAME) /usr/local/bin/

# Show help
help:
	@echo "Available targets:"
	@echo "  all       - Clean and build (default)"
	@echo "  build     - Build the binary"
	@echo "  linux     - Build for all Linux architectures"
	@echo "  clean     - Remove build artifacts"
	@echo "  deps      - Install dependencies"
	@echo "  run       - Build and run the application"
	@echo "  test      - Run tests"
	@echo "  fmt       - Format code"
	@echo "  install   - Install the binary to /usr/local/bin"
	@echo "  help      - Show this help message"

.PHONY: all build linux clean deps run test fmt install help 