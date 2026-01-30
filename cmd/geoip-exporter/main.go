// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/geoip-exporter-ebpf/internal/collector"
	"github.com/geoip-exporter-ebpf/internal/log"
)

var (
	interfaces     = flag.String("interfaces", "any", "Comma-separated interface names; 'any' = all non-loopback")
	geoipDB        = flag.String("geoip-db", "/usr/share/GeoIP/GeoLite2-Country.mmdb", "Path to GeoLite2-Country.mmdb")
	mapMaxEntries  = flag.Int("map-max-entries", 100000, "eBPF LRU map max entries")
	pollInterval   = flag.Duration("poll-interval", 2*time.Second, "Interval to read kernel map and update metrics")
	logLevel       = flag.String("log-level", "info", "Log level: debug, info, warn, error")
	listenAddress  = flag.String("listen-address", "0.0.0.0:9100", "HTTP server listen address for /metrics")
	metricsPath    = flag.String("metrics-path", "/metrics", "HTTP path for Prometheus metrics")
	flowBatchSize  = flag.Int("flow-batch-size", 10000, "Keys per batch lookup syscall")
	geoipCacheSize = flag.Int("geoip-cache-size", 65536, "GeoIP LRU cache size (prefix → country)")
)

func main() {
	flag.Parse()

	// Configure logging
	if err := log.Configure(*logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "invalid log level: %v\n", err)
		os.Exit(1)
	}
	slog.Debug("logging configured", "level", *logLevel)

	slog.Info("starting geoip-exporter",
		"interfaces", *interfaces,
		"geoip_db", *geoipDB,
		"listen", *listenAddress,
		"poll_interval", *pollInterval,
	)
	slog.Debug("config",
		"map_max_entries", *mapMaxEntries,
		"metrics_path", *metricsPath,
	)

	// Create collector config
	cfg := collector.Config{
		Interfaces:     *interfaces,
		GeoIPDB:        *geoipDB,
		MapMaxEntries:  *mapMaxEntries,
		PollInterval:   *pollInterval,
		ListenAddress:  *listenAddress,
		MetricsPath:    *metricsPath,
		FlowBatchSize:  *flowBatchSize,
		GeoIPCacheSize: *geoipCacheSize,
	}

	// Run collector (blocks until context is canceled)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := collector.Run(ctx, cfg); err != nil {
		slog.Error("collector run failed", "err", err)
		os.Exit(1)
	}

	slog.Info("shutdown complete")
}
