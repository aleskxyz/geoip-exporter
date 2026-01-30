// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package bpf

import "github.com/cilium/ebpf"

// Objects is the exported type for loaded eBPF objects (alias of geoipObjects).
type Objects = geoipObjects

// LoadGeoip returns the embedded CollectionSpec for geoip.
// Caller may modify spec (e.g. Maps.FlowMap.MaxEntries) before LoadAndAssign.
func LoadGeoip() (*ebpf.CollectionSpec, error) {
	return loadGeoip()
}
