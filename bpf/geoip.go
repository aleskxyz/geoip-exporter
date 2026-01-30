// Package bpf contains the eBPF TC program for GeoIP traffic accounting.
// Regenerate with: make generate-ebpf-all (generates for amd64+arm64)
// Or single arch: make generate-ebpf ARCH=amd64 (or arm64)
// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -cc clang -go-package bpf -no-global-types geoip c/geoip_tc.c -- -I/usr/include -I/usr/include/bpf -I/usr/include/x86_64-linux-gnu -I/usr/include/aarch64-linux-gnu
