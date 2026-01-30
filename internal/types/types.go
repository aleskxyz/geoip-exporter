// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package types

// FlowKey matches struct flow_key in bpf/c/geoip_tc.c.
// Addr stores IP prefix: IPv4 uses first 3 bytes (/24), IPv6 uses 6 bytes (/48).
type FlowKey struct {
	IpVersion uint8
	Dir       uint8
	_         [2]byte
	Ifindex   uint32
	Addr      [6]byte
	_         [2]byte
}

// FlowValue matches struct flow_value in bpf/c/geoip_tc.c.
type FlowValue struct {
	Packets    uint64
	Bytes      uint64
	LastSeenNs uint64
}

const (
	DirRX = 0
	DirTX = 1
)

const (
	StatPacketsSeen = 0
	StatLookupFail  = 1
	StatUpdateFail  = 2
	// Indices 3-4 (IPv4/IPv6 packet counts) are tracked by eBPF but not exposed as metrics
	StatNewKeys          = 5
	StatEvictionPressure = 6
	NumStats             = 7
)
