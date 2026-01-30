// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package collector

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	InterfaceStatusUp       = 0
	InterfaceStatusDown     = 1
	InterfaceStatusNotFound = 2
)

type metrics struct {
	bytesReceived          *prometheus.CounterVec
	bytesSent              *prometheus.CounterVec
	packetsTotal           prometheus.Counter
	lookupFailTotal        prometheus.Counter
	updateFailTotal        prometheus.Counter
	newKeysTotal           prometheus.Counter
	evictionsTotal         prometheus.Counter
	mapEntries             prometheus.Gauge
	evictionMinAgeSeconds  prometheus.Gauge
	mapReadDurationSeconds prometheus.Gauge
	interfaceStatus        *prometheus.GaugeVec
	configMapMaxEntries    prometheus.Gauge
	configPollInterval     prometheus.Gauge
	configFlowBatchSize    prometheus.Gauge
}

func newMetrics() *metrics {
	return &metrics{
		bytesReceived: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "geoip_bytes_received_total",
				Help: "Total bytes received (monotonic), by country, interface, ip_version.",
			},
			[]string{"country", "interface", "ip_version"},
		),
		bytesSent: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "geoip_bytes_sent_total",
				Help: "Total bytes sent (monotonic), by country, interface, ip_version.",
			},
			[]string{"country", "interface", "ip_version"},
		),
		packetsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "geoip_ebpf_packets_total",
				Help: "Internal: total packets seen by eBPF.",
			},
		),
		lookupFailTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "geoip_ebpf_lookup_fail_total",
				Help: "Internal: lookup failures in eBPF.",
			},
		),
		updateFailTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "geoip_ebpf_update_fail_total",
				Help: "Internal: update failures in eBPF.",
			},
		),
		newKeysTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "geoip_ebpf_new_keys_total",
				Help: "Internal: new keys created in eBPF map.",
			},
		),
		evictionsTotal: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "geoip_ebpf_evictions_total",
				Help: "Internal: eviction pressure count.",
			},
		),
		mapEntries: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_ebpf_map_entries",
				Help: "Internal: current flow map entry count.",
			},
		),
		evictionMinAgeSeconds: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_ebpf_minimum_eviction_age_seconds",
				Help: "Internal: minimum age in seconds among evicted flows. Should be greater than poll interval; lower indicates evicting recently-seen flows. Value is +Inf initially and retains the last known minimum eviction age until new evictions occur.",
			},
		),
		mapReadDurationSeconds: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_ebpf_map_read_duration_seconds",
				Help: "Time in seconds to read the flow map (batch lookup iteration) in the last poll.",
			},
		),
		interfaceStatus: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "geoip_interface_status",
				Help: "Interface status: 0=up, 1=down, 2=not found. Reported for configured interfaces (explicit list) or all non-loopback (any mode).",
			},
			[]string{"interface"},
		),
		configMapMaxEntries: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_config_map_max_entries",
				Help: "Configured maximum entries in the eBPF flow map.",
			},
		),
		configPollInterval: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_config_poll_interval_seconds",
				Help: "Configured poll interval in seconds.",
			},
		),
		configFlowBatchSize: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "geoip_config_flow_batch_size",
				Help: "Configured number of keys per batch lookup syscall.",
			},
		),
	}
}

func (m *metrics) register() {
	prometheus.MustRegister(
		m.bytesReceived,
		m.bytesSent,
		m.packetsTotal,
		m.lookupFailTotal,
		m.updateFailTotal,
		m.newKeysTotal,
		m.evictionsTotal,
		m.mapEntries,
		m.evictionMinAgeSeconds,
		m.mapReadDurationSeconds,
		m.interfaceStatus,
		m.configMapMaxEntries,
		m.configPollInterval,
		m.configFlowBatchSize,
	)
	slog.Info("Prometheus metrics registered")
}
