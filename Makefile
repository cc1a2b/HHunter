.PHONY: build clean install test run help release

BINARY_NAME=hhunter
BUILD_DIR=build
GO=go
CMD=./cmd/hhunter
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-s -w -X main.version=$(VERSION)

help:
	@echo "HHunter $(VERSION) - HTTP Header Security Testing Engine"
	@echo ""
	@echo "Available targets:"
	@echo "  build       - Build the binary"
	@echo "  clean       - Remove build artifacts"
	@echo "  install     - Install dependencies"
	@echo "  test        - Run tests"
	@echo "  run         - Run with example target"
	@echo "  release     - Build release archives for all platforms"
	@echo "  help        - Show this help message"

build:
	@echo "Building HHunter $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD)
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
	./$(BUILD_DIR)/$(BINARY_NAME) -u https://httpbin.org/headers --auth --proxy

# Release builds — produces archives matching what the updater expects
release: clean
	@echo "Building release $(VERSION) for all platforms..."
	@mkdir -p $(BUILD_DIR)

	GOOS=linux GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD)
	tar czf $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64
	@rm $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64

	GOOS=linux GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD)
	tar czf $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-arm64
	@rm $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64

	GOOS=darwin GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD)
	tar czf $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64
	@rm $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64

	GOOS=darwin GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD)
	tar czf $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-arm64
	@rm $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64

	GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD)
	cd $(BUILD_DIR) && zip $(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe && rm $(BINARY_NAME)-windows-amd64.exe

	GOOS=windows GOARCH=arm64 $(GO) build -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-arm64.exe $(CMD)
	cd $(BUILD_DIR) && zip $(BINARY_NAME)-windows-arm64.zip $(BINARY_NAME)-windows-arm64.exe && rm $(BINARY_NAME)-windows-arm64.exe

	cd $(BUILD_DIR) && sha256sum *.tar.gz *.zip > checksums.txt

	@echo ""
	@echo "Release $(VERSION) built:"
	@ls -lh $(BUILD_DIR)/
