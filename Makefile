.PHONY: all build install uninstall generate-ebpf-all generate-ebpf docker docker-build docker-run docker-stop docker-logs docker-clean clean check test fmt lint help

# Variables
BINARY_NAME=geoip-exporter
DOCKER_IMAGE=geoip-exporter:latest
DOCKER_CONTAINER=geoip-exporter
ARCH ?= $(shell go env GOARCH)

all: build

# Generate eBPF code for all architectures (local development)
generate-ebpf-all:
	@echo "Generating eBPF code for amd64+arm64..."
	cd bpf && go generate .

# Generate eBPF code for single architecture (Docker/CI)
generate-ebpf:
	@echo "Generating eBPF code for $(ARCH)..."
	@if [ "$(ARCH)" = "amd64" ]; then \
		GNU_ARCH="x86_64-linux-gnu"; \
	elif [ "$(ARCH)" = "arm64" ]; then \
		GNU_ARCH="aarch64-linux-gnu"; \
	else \
		echo "Error: Unsupported architecture $(ARCH)"; exit 1; \
	fi; \
	cd bpf && go run github.com/cilium/ebpf/cmd/bpf2go \
		-target $(ARCH) \
		-cc clang \
		-go-package bpf \
		-no-global-types \
		geoip c/geoip_tc.c \
		-- -I/usr/include -I/usr/include/bpf -I/usr/include/$$GNU_ARCH

# Build binary locally
build: generate-ebpf-all
	@echo "Building Go binary (static)..."
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o $(BINARY_NAME) ./cmd/geoip-exporter
	@echo "Build complete: ./$(BINARY_NAME)"

# Install binary to system
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	install -m 755 $(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed: /usr/local/bin/$(BINARY_NAME)"

# Uninstall binary from system
uninstall:
	@echo "Removing $(BINARY_NAME) from /usr/local/bin..."
	rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstalled."

# Build Docker image
docker: docker-build

docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .
	@echo "Docker image built: $(DOCKER_IMAGE)"

# Run Docker container
docker-run:
	@echo "Running Docker container..."
	docker-compose up -d
	@echo "Container started. Logs: docker logs -f $(DOCKER_CONTAINER)"

# Stop Docker container
docker-stop:
	@echo "Stopping Docker container..."
	docker-compose down
	@echo "Container stopped."

# View Docker logs
docker-logs:
	docker logs -f $(DOCKER_CONTAINER)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	rm -f bpf/*.o
	rm -f bpf/*_bpfel.go bpf/*_bpfeb.go
	@echo "Clean complete."

# Check required tools
check:
	@echo "Checking required tools..."
	@command -v go >/dev/null 2>&1 || { echo "Error: go is not installed"; exit 1; }
	@command -v clang >/dev/null 2>&1 || { echo "Error: clang is not installed"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed"; exit 1; }
	@echo "✓ go: $$(go version)"
	@echo "✓ clang: $$(clang --version | head -1)"
	@echo "✓ docker: $$(docker --version)"
	@echo "All required tools are installed."

# Clean Docker resources
docker-clean:
	@echo "Cleaning Docker resources..."
	docker-compose down -v
	docker rmi $(DOCKER_IMAGE) || true
	@echo "Docker cleanup complete."

# Run tests
test:
	go test ./...

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	go vet ./...

# Help
help:
	@echo "GeoIP Exporter eBPF - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build targets:"
	@echo "  all (default)      - Same as 'build'"
	@echo "  build              - Build binary locally (generates eBPF for all archs)"
	@echo "  install            - Install binary to /usr/local/bin (requires sudo)"
	@echo "  uninstall          - Remove binary from /usr/local/bin (requires sudo)"
	@echo "  generate-ebpf-all  - Generate eBPF code for amd64+arm64"
	@echo "  generate-ebpf      - Generate eBPF code for single arch (ARCH=amd64|arm64)"
	@echo ""
	@echo "Docker targets:"
	@echo "  docker             - Build Docker image (alias for docker-build)"
	@echo "  docker-build       - Build Docker image"
	@echo "  docker-run         - Run Docker container with docker-compose"
	@echo "  docker-stop        - Stop Docker container"
	@echo "  docker-logs        - View Docker container logs"
	@echo "  docker-clean       - Remove Docker image and containers"
	@echo ""
	@echo "Development targets:"
	@echo "  check              - Verify required tools are installed"
	@echo "  test               - Run tests"
	@echo "  fmt                - Format code with go fmt"
	@echo "  lint               - Lint code with go vet"
	@echo "  clean              - Clean build artifacts"
	@echo ""
	@echo "Other:"
	@echo "  help               - Show this help message"
