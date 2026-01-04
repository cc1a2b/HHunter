.PHONY: build clean install test run help

BINARY_NAME=hhunter
BUILD_DIR=build
GO=go

help:
	@echo "HHunter - Advanced Header Testing Engine"
	@echo ""
	@echo "Available targets:"
	@echo "  build    - Build the binary"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install dependencies"
	@echo "  test     - Run tests"
	@echo "  run      - Run with example target"
	@echo "  help     - Show this help message"

build:
	@echo "Building HHunter..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f *.json
	@echo "Clean complete"

install:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "Dependencies installed"

test:
	@echo "Running tests..."
	$(GO) test -v ./...

run: build
	@echo "Running HHunter example scan..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan -u https://httpbin.org/headers --auth --proxy

# Platform-specific builds
build-linux:
	GOOS=linux GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-linux .

build-windows:
	GOOS=windows GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME).exe .

build-darwin:
	GOOS=darwin GOARCH=amd64 $(GO) build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin .

build-all: build-linux build-windows build-darwin
	@echo "All platform builds complete"
