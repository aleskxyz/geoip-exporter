// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package geoip

import (
	"log/slog"
	"net"
	"sync"

	"github.com/oschwald/geoip2-golang"
)

const (
	defaultCacheSize = 65536
	unknown          = "UNKNOWN"
)

// Lookup provides GeoIP country lookup with LRU cache.
// Uses MaxMind GeoLite2-Country; unknown/private → "UNKNOWN".
// If DB open fails, callers should handle nil Lookup.
type Lookup struct {
	mu    sync.RWMutex
	db    *geoip2.Reader
	cache *lruCache
}

// NewWithCacheSize opens the MaxMind GeoLite2-Country database at path.
// If cacheSize <= 0, defaultCacheSize (65536) is used.
func NewWithCacheSize(path string, cacheSize int) (*Lookup, error) {
	if cacheSize <= 0 {
		cacheSize = defaultCacheSize
	}
	slog.Debug("opening GeoIP database", "path", path, "cache_size", cacheSize)
	db, err := geoip2.Open(path)
	if err != nil {
		slog.Error("GeoIP database open failed", "path", path, "err", err)
		return nil, err
	}
	slog.Info("GeoIP database opened", "path", path)
	return &Lookup{
		db:    db,
		cache: newLRUCache(cacheSize),
	}, nil
}

func (l *Lookup) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.db == nil {
		slog.Debug("GeoIP Close: already closed")
		return nil
	}
	slog.Debug("closing GeoIP database")
	err := l.db.Close()
	l.db = nil
	if err != nil {
		slog.Error("GeoIP database close failed", "err", err)
		return err
	}
	slog.Info("GeoIP database closed")
	return nil
}

// LookupV4 returns the country code for an IPv4 address.
// flowDesc is optional and used for debug logging (e.g. "RX eth0").
func (l *Lookup) LookupV4(addr [4]byte, flowDesc string) string {
	if l == nil {
		slog.Debug("LookupV4: nil Lookup")
		return unknown
	}
	ip := net.IP(addr[:])
	if key, ok := l.cache.getV4(addr); ok {
		if flowDesc != "" {
			slog.Debug("LookupV4 cache hit", "ip", ip.String(), "country", key, "flow", flowDesc)
		} else {
			slog.Debug("LookupV4 cache hit", "ip", ip.String(), "country", key)
		}
		return key
	}
	if flowDesc != "" {
		slog.Debug("LookupV4 cache miss, querying DB", "ip", ip.String(), "flow", flowDesc)
	} else {
		slog.Debug("LookupV4 cache miss, querying DB", "ip", ip.String())
	}
	l.mu.RLock()
	db := l.db
	l.mu.RUnlock()
	if db == nil {
		slog.Warn("LookupV4: database closed", "ip", ip.String())
		return unknown
	}
	record, err := db.Country(ip)
	if err != nil {
		slog.Warn("LookupV4 Country lookup failed", "ip", ip.String(), "err", err)
		l.cache.putV4(addr, unknown)
		return unknown
	}
	cc := unknown
	if record.Country.IsoCode != "" {
		cc = record.Country.IsoCode
	}
	l.cache.putV4(addr, cc)
	return cc
}

// LookupV6 returns the country code for an IPv6 address.
// flowDesc is optional and used for debug logging.
func (l *Lookup) LookupV6(addr [16]byte, flowDesc string) string {
	if l == nil {
		slog.Debug("LookupV6: nil Lookup")
		return unknown
	}
	ip := net.IP(addr[:])
	if key, ok := l.cache.getV6(addr); ok {
		if flowDesc != "" {
			slog.Debug("LookupV6 cache hit", "ip", ip.String(), "country", key, "flow", flowDesc)
		} else {
			slog.Debug("LookupV6 cache hit", "ip", ip.String(), "country", key)
		}
		return key
	}
	if flowDesc != "" {
		slog.Debug("LookupV6 cache miss, querying DB", "ip", ip.String(), "flow", flowDesc)
	} else {
		slog.Debug("LookupV6 cache miss, querying DB", "ip", ip.String())
	}
	l.mu.RLock()
	db := l.db
	l.mu.RUnlock()
	if db == nil {
		slog.Warn("LookupV6: database closed", "ip", ip.String())
		return unknown
	}
	record, err := db.Country(ip)
	if err != nil {
		slog.Warn("LookupV6 Country lookup failed", "ip", ip.String(), "err", err)
		l.cache.putV6(addr, unknown)
		return unknown
	}
	cc := unknown
	if record.Country.IsoCode != "" {
		cc = record.Country.IsoCode
	}
	l.cache.putV6(addr, cc)
	return cc
}
