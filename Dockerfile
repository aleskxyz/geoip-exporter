# syntax=docker/dockerfile:1

# Stage 1: Build eBPF and Go binary
FROM golang:1.23-alpine AS builder

# Docker buildx provides TARGETARCH automatically
ARG TARGETARCH

# Install build dependencies
RUN apk add --no-cache \
    clang \
    llvm \
    libbpf-dev \
    linux-headers \
    make \
    git

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate eBPF code for target architecture only
RUN make generate-ebpf ARCH="$TARGETARCH"

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o geoip-exporter ./cmd/geoip-exporter

# Stage 2: Runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/geoip-exporter /app/geoip-exporter

# Create directory for GeoIP database
RUN mkdir -p /usr/share/GeoIP

# Expose Prometheus metrics port
EXPOSE 9100

# Default command (runs as root, required for eBPF capabilities)
ENTRYPOINT ["/app/geoip-exporter"]
CMD []
