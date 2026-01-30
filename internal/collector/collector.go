// SPDX-License-Identifier: GPL-3.0
// Copyright (C) 2026 GeoIP Exporter Contributors

package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/geoip-exporter-ebpf/bpf"
	"github.com/geoip-exporter-ebpf/internal/geoip"
	"github.com/geoip-exporter-ebpf/internal/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

// Config is read-only after Run() is called and safe for concurrent reads.
// All fields must be initialized before calling Run() and must not be modified.
type Config struct {
	Interfaces     string
	GeoIPDB        string
	MapMaxEntries  int
	PollInterval   time.Duration
	ListenAddress  string
	MetricsPath    string
	FlowBatchSize  int // keys per BatchLookup (0 = default 2048)
	GeoIPCacheSize int // GeoIP LRU cache size (0 = default 65536)
}

type Collector struct {
	cfg                   Config
	objs                  *bpf.Objects
	linksByIface          map[int][]link.Link // ifindex -> [ingress, egress]; enables cleanup when interface is removed
	attachedIfaces        map[int]struct{}    // when interfaces=="any", track so we can attach to new ones
	linksMu               sync.Mutex
	geo                   *geoip.Lookup
	metrics               *metrics
	shadow                map[flowKeyShadow]flowValShadow
	countryCache          map[flowKeyShadow]string // country by flow key; only lookup GeoIP for new keys
	prevStats             [types.NumStats]uint64   // previous kernel stats for counter deltas
	lastMinEvictionAgeSec float64                  // last known minimum eviction age; sticky until next eviction
	shadowMu              sync.Mutex               // protects shadow, countryCache, prevStats, lastMinEvictionAgeSec
	ifNameMap             map[int]string           // ifindex -> stable name
	ifNameMu              sync.Mutex               // protects ifNameMap
}

type flowKeyShadow struct {
	IpVersion uint8
	Dir       uint8
	Ifindex   uint32
	Addr      [6]byte
}

type flowValShadow struct {
	Packets    uint64
	Bytes      uint64
	LastSeenNs uint64
	LastPollAt time.Time
}

func Run(ctx context.Context, cfg Config) error {
	if cfg.MapMaxEntries <= 0 {
		return fmt.Errorf("--map-max-entries must be > 0, got %d", cfg.MapMaxEntries)
	}
	if cfg.PollInterval <= 0 {
		return fmt.Errorf("--poll-interval must be > 0, got %v", cfg.PollInterval)
	}

	if err := checkKernelVersion(); err != nil {
		slog.Error("kernel version check failed", "err", err)
		return err
	}

	spec, err := bpf.LoadGeoip()
	if err != nil {
		slog.Error("load eBPF spec failed", "err", err)
		return fmt.Errorf("load eBPF: %w", err)
	}
	slog.Info("eBPF spec loaded", "map_max_entries", cfg.MapMaxEntries)
	if m, ok := spec.Maps["flow_map"]; ok {
		m.MaxEntries = uint32(cfg.MapMaxEntries)
	}

	var objs bpf.Objects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		slog.Error("load eBPF objects failed", "err", err)
		return fmt.Errorf("load eBPF objects: %w", err)
	}
	defer objs.Close()
	slog.Debug("eBPF objects loaded and assigned")
	slog.Info("eBPF programs and maps loaded")

	geo, err := geoip.NewWithCacheSize(cfg.GeoIPDB, cfg.GeoIPCacheSize)
	if err != nil {
		slog.Warn("geoip db open failed, using UNKNOWN for all", "path", cfg.GeoIPDB, "err", err)
		geo = nil
	} else {
		defer geo.Close()
		slog.Info("geoip database loaded", "path", cfg.GeoIPDB)
	}

	// skipMissing=true allows startup even if configured interfaces don't exist yet
	interfaces, err := resolveInterfaces(cfg.Interfaces, true)
	if err != nil {
		slog.Error("resolve interfaces failed", "err", err, "config", cfg.Interfaces)
		return fmt.Errorf("interfaces: %w", err)
	}
	slog.Debug("interfaces resolved", "count", len(interfaces), "names", interfaceNames(interfaces))
	if len(interfaces) == 0 {
		slog.Info("no interfaces found yet", "config", cfg.Interfaces)
	} else {
		slog.Info("interfaces resolved", "count", len(interfaces), "names", interfaceNames(interfaces))
	}

	c := &Collector{
		cfg:                   cfg,
		objs:                  &objs,
		geo:                   geo,
		metrics:               newMetrics(),
		shadow:                make(map[flowKeyShadow]flowValShadow),
		countryCache:          make(map[flowKeyShadow]string),
		ifNameMap:             make(map[int]string),
		linksByIface:          make(map[int][]link.Link),
		attachedIfaces:        make(map[int]struct{}),
		lastMinEvictionAgeSec: math.Inf(1),
	}
	c.metrics.register()
	c.metrics.configMapMaxEntries.Set(float64(cfg.MapMaxEntries))
	c.metrics.configPollInterval.Set(cfg.PollInterval.Seconds())
	c.metrics.configFlowBatchSize.Set(float64(cfg.FlowBatchSize))
	c.metrics.evictionMinAgeSeconds.Set(math.Inf(1))

	c.linksMu.Lock()
	if err := c.attachTCLocked(interfaces); err != nil {
		c.linksMu.Unlock()
		slog.Error("attach TC failed", "err", err)
		return fmt.Errorf("attach TC: %w", err)
	}
	for _, iface := range interfaces {
		c.setIfName(iface.Index, stableInterfaceName(iface))
		c.attachedIfaces[iface.Index] = struct{}{}
	}
	c.linksMu.Unlock()
	defer c.detachTC()

	names := make([]string, 0, len(interfaces))
	for _, iface := range interfaces {
		names = append(names, iface.Name+" (index "+fmt.Sprint(iface.Index)+")")
	}
	msg := "TC attached; listening on interfaces"
	if c.cfg.Interfaces == "any" {
		justNames := make([]string, len(interfaces))
		for i, iface := range interfaces {
			justNames[i] = iface.Name
		}
		msg = "TC attached; listening on any (all non-loopback) interfaces: " + strings.Join(justNames, ", ")
	}
	if len(interfaces) > 0 {
		slog.Info(msg, "interfaces", names)
	}

	mux := http.NewServeMux()
	mux.Handle(cfg.MetricsPath, promhttp.HandlerFor(
		prometheus.DefaultGatherer,
		promhttp.HandlerOpts{EnableOpenMetrics: true},
	))
	srv := &http.Server{Addr: cfg.ListenAddress, Handler: mux}
	slog.Debug("HTTP server starting", "listen", cfg.ListenAddress, "metrics_path", cfg.MetricsPath)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
		}
	}()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShutdown()
	defer srv.Shutdown(shutdownCtx)

	ticker := time.NewTicker(cfg.PollInterval)
	defer ticker.Stop()
	slog.Debug("poll loop started", "interval", cfg.PollInterval)
	for {
		select {
		case <-ctx.Done():
			slog.Debug("context canceled, exiting poll loop")
			return ctx.Err()
		case <-ticker.C:
			slog.Debug("ticker fired, calling poll")
			err := c.poll(ctx)
			slog.Debug("poll returned", "err", err)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return err
				}
				slog.Error("poll", "err", err)
			}
		}
	}
}

// attachTCLocked attaches TC programs. Caller must hold c.linksMu.
func (c *Collector) attachTCLocked(interfaces []net.Interface) error {
	for _, iface := range interfaces {
		slog.Debug("attach TC ingress", "iface", iface.Name, "index", iface.Index)
		ingress, err := link.AttachTCX(link.TCXOptions{
			Program:   c.objs.TcIngress,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			slog.Error("attach TC ingress failed", "iface", iface.Name, "index", iface.Index, "err", err)
			return fmt.Errorf("attach ingress %s (index %d): %w", iface.Name, iface.Index, err)
		}
		slog.Debug("attach TC egress", "iface", iface.Name, "index", iface.Index)
		egress, err := link.AttachTCX(link.TCXOptions{
			Program:   c.objs.TcEgress,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			ingress.Close()
			slog.Error("attach TC egress failed", "iface", iface.Name, "index", iface.Index, "err", err)
			return fmt.Errorf("attach egress %s (index %d): %w", iface.Name, iface.Index, err)
		}
		c.linksByIface[iface.Index] = []link.Link{ingress, egress}
		slog.Debug("TC attached to interface", "iface", iface.Name, "index", iface.Index)
	}
	return nil
}

// resolveInterfaces converts config string to interface list.
// "any" returns all non-loopback interfaces. For explicit names, skipMissing controls error behavior.
func resolveInterfaces(cfg string, skipMissing bool) ([]net.Interface, error) {
	all, err := net.Interfaces()
	if err != nil {
		slog.Error("net.Interfaces failed", "err", err)
		return nil, err
	}
	slog.Debug("listed network interfaces", "count", len(all))
	if cfg == "any" {
		var out []net.Interface
		for _, iface := range all {
			if iface.Flags&net.FlagLoopback == 0 {
				out = append(out, iface)
			}
		}
		slog.Debug("interfaces filter any: non-loopback", "matched", len(out))
		return out, nil
	}
	names := strings.Split(cfg, ",")
	byName := make(map[string]net.Interface)
	for _, iface := range all {
		byName[iface.Name] = iface
	}
	var out []net.Interface
	seen := make(map[string]struct{}) // Deduplicate interface names
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			continue // Skip duplicate names
		}
		seen[name] = struct{}{}
		if iface, ok := byName[name]; ok {
			out = append(out, iface)
		} else {
			if skipMissing {
				slog.Debug("interface not found, skipping", "name", name)
			} else {
				slog.Error("interface not found", "name", name, "err", "not in system")
				return nil, fmt.Errorf("interface %q not found", name)
			}
		}
	}
	slog.Debug("interfaces resolved by name", "requested", names, "resolved", len(out))
	return out, nil
}

func (c *Collector) detachTC() {
	c.linksMu.Lock()
	defer c.linksMu.Unlock()
	n := 0
	slog.Debug("detaching TC", "link_count", len(c.linksByIface)*2)
	for _, links := range c.linksByIface {
		for _, l := range links {
			l.Close()
			n++
		}
	}
	c.linksByIface = make(map[int][]link.Link)
	c.attachedIfaces = make(map[int]struct{})
	slog.Info("TC detached", "links", n)
}

func (c *Collector) setIfName(ifindex int, name string) {
	c.ifNameMu.Lock()
	defer c.ifNameMu.Unlock()
	c.ifNameMap[ifindex] = name
}

func (c *Collector) getIfName(ifindex int) string {
	c.ifNameMu.Lock()
	defer c.ifNameMu.Unlock()
	if name, ok := c.ifNameMap[ifindex]; ok {
		return name
	}
	return fmt.Sprintf("%d", ifindex)
}

// ensureInterfacesAttached manages dynamic interface attachment/detachment.
// Detaches from removed/renamed interfaces; attaches to new ones in "any" mode.
func (c *Collector) ensureInterfacesAttached() error {
	all, err := net.Interfaces()
	if err != nil {
		slog.Error("ensureInterfaces list failed", "err", err)
		return err
	}
	currentIndexes := make(map[int]struct{})
	for _, iface := range all {
		currentIndexes[iface.Index] = struct{}{}
	}

	// For explicit list, only stay attached to interfaces with configured names (renames are treated as deletions)
	var interfacesFromConfig []net.Interface
	wantedIndexes := make(map[int]struct{})
	if c.cfg.Interfaces != "any" {
		var resolveErr error
		interfacesFromConfig, resolveErr = resolveInterfaces(c.cfg.Interfaces, true)
		if resolveErr != nil {
			slog.Error("ensureInterfaces resolve failed", "interfaces", c.cfg.Interfaces, "err", resolveErr)
			return resolveErr
		}
		for _, iface := range interfacesFromConfig {
			wantedIndexes[iface.Index] = struct{}{}
		}
	}

	// Pre-fetch names to avoid nested locking
	detachNames := make(map[int]string)
	for ifindex := range c.attachedIfaces {
		_, stillExists := currentIndexes[ifindex]
		stillWanted := true
		if c.cfg.Interfaces != "any" {
			_, stillWanted = wantedIndexes[ifindex]
		}
		if !stillExists || !stillWanted {
			detachNames[ifindex] = c.getIfName(ifindex)
		}
	}

	c.linksMu.Lock()

	var toDetach []int
	for ifindex := range c.attachedIfaces {
		stillExists := false
		if _, ok := currentIndexes[ifindex]; ok {
			stillExists = true
		}
		stillWanted := true
		if c.cfg.Interfaces != "any" {
			if _, ok := wantedIndexes[ifindex]; !ok {
				stillWanted = false
			}
		}
		if !stillExists || !stillWanted {
			toDetach = append(toDetach, ifindex)
		}
	}

	for _, ifindex := range toDetach {
		links := c.linksByIface[ifindex]
		name := detachNames[ifindex]
		for _, l := range links {
			l.Close()
		}
		delete(c.linksByIface, ifindex)
		delete(c.attachedIfaces, ifindex)
		_, stillExists := currentIndexes[ifindex]
		_, stillWanted := wantedIndexes[ifindex]
		if c.cfg.Interfaces == "any" {
			stillWanted = true // not applicable in any mode
		}
		reason := "removed"
		if stillExists && !stillWanted {
			reason = "renamed or no longer matches config"
		}
		slog.Info("detached TC from interface", "iface", name, "index", ifindex, "reason", reason)
	}

	// Clean up ifNameMap after releasing linksMu
	c.linksMu.Unlock()
	if len(toDetach) > 0 {
		c.ifNameMu.Lock()
		for _, ifindex := range toDetach {
			delete(c.ifNameMap, ifindex)
		}
		c.ifNameMu.Unlock()
	}
	c.linksMu.Lock()

	var interfaces []net.Interface
	if c.cfg.Interfaces == "any" {
		slog.Debug("ensureInterfaces resolving any")
		interfaces, err = resolveInterfaces("any", false)
		if err != nil {
			c.linksMu.Unlock()
			slog.Error("ensureInterfaces resolve any failed", "err", err)
			return err
		}
	} else {
		interfaces = interfacesFromConfig
	}

	var newlyAttached []net.Interface
	for _, iface := range interfaces {
		if _, attached := c.attachedIfaces[iface.Index]; attached {
			continue
		}
		ingress, err := link.AttachTCX(link.TCXOptions{
			Program:   c.objs.TcIngress,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			slog.Warn("attach ingress to new interface failed", "iface", iface.Name, "index", iface.Index, "err", err)
			continue
		}
		egress, err := link.AttachTCX(link.TCXOptions{
			Program:   c.objs.TcEgress,
			Interface: iface.Index,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			ingress.Close()
			slog.Warn("attach egress to new interface failed", "iface", iface.Name, "index", iface.Index, "err", err)
			continue
		}
		c.linksByIface[iface.Index] = []link.Link{ingress, egress}
		c.attachedIfaces[iface.Index] = struct{}{}
		newlyAttached = append(newlyAttached, iface)
		slog.Info("attached TC to new interface", "iface", iface.Name, "index", iface.Index)
	}
	c.linksMu.Unlock()

	for _, iface := range newlyAttached {
		c.setIfName(iface.Index, stableInterfaceName(iface))
	}
	return nil
}

// flowKeySize must match kernel map key size (struct flow_key + alignment = 16 bytes)
const flowKeySize = 16

const defaultFlowBatchSize = 2048

func keyFromBytes(b []byte) types.FlowKey {
	var k types.FlowKey
	if len(b) < flowKeySize {
		return k
	}
	k.IpVersion = b[0]
	k.Dir = b[1]
	k.Ifindex = binary.LittleEndian.Uint32(b[4:8])
	copy(k.Addr[:], b[8:14])
	return k
}

// addFlowToCurrent sums per-CPU values. If a key appears multiple times during batch iteration
// (kernel updated map concurrently), keeps the view with newer lastSeenNs.
func addFlowToCurrent(keyBuf []byte, values []types.FlowValue, current map[flowKeyShadow]flowValShadow, now time.Time) {
	key := keyFromBytes(keyBuf)
	sk := flowKeyShadow{
		IpVersion: key.IpVersion,
		Dir:       key.Dir,
		Ifindex:   key.Ifindex,
		Addr:      key.Addr,
	}
	var packets, bytes, lastSeenNs uint64
	for i := range values {
		packets += values[i].Packets
		bytes += values[i].Bytes
		if values[i].LastSeenNs > lastSeenNs {
			lastSeenNs = values[i].LastSeenNs
		}
	}
	next := flowValShadow{
		Packets:    packets,
		Bytes:      bytes,
		LastSeenNs: lastSeenNs,
		LastPollAt: now,
	}
	if prev, seen := current[sk]; seen {
		if prev.LastSeenNs > next.LastSeenNs {
			next = prev
		}
	}
	current[sk] = next
}

func (c *Collector) updateInterfaceStatusMetric() {
	all, err := net.Interfaces()
	if err != nil {
		slog.Debug("interface status metric: list failed", "err", err)
		return
	}
	byName := make(map[string]net.Interface)
	for _, iface := range all {
		byName[iface.Name] = iface
	}
	var namesToReport []string
	if c.cfg.Interfaces == "any" {
		// Only report existing interfaces (0 or 1); drop labels for interfaces that disappear (no 2).
		c.metrics.interfaceStatus.Reset()
		for _, iface := range all {
			if iface.Flags&net.FlagLoopback == 0 {
				namesToReport = append(namesToReport, iface.Name)
			}
		}
	} else {
		seen := make(map[string]struct{})
		for _, name := range strings.Split(c.cfg.Interfaces, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				if _, exists := seen[name]; !exists {
					seen[name] = struct{}{}
					namesToReport = append(namesToReport, name)
				}
			}
		}
	}
	for _, name := range namesToReport {
		status := float64(InterfaceStatusNotFound)
		if iface, ok := byName[name]; ok {
			if iface.Flags&net.FlagUp != 0 {
				status = float64(InterfaceStatusUp)
			} else {
				status = float64(InterfaceStatusDown)
			}
		}
		c.metrics.interfaceStatus.WithLabelValues(name).Set(status)
	}
}

func (c *Collector) poll(ctx context.Context) error {
	slog.Debug("poll start")
	if err := ctx.Err(); err != nil {
		slog.Debug("poll exit", "reason", "context canceled")
		return err
	}
	if err := c.ensureInterfacesAttached(); err != nil {
		slog.Debug("ensure interfaces", "err", err)
	}
	c.updateInterfaceStatusMetric()
	now := time.Now()
	current := make(map[flowKeyShadow]flowValShadow)

	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil || possibleCPUs <= 0 {
		return fmt.Errorf("flow map batch lookup requires PossibleCPU: %w", err)
	}

	flowBatchSize := c.cfg.FlowBatchSize
	if flowBatchSize <= 0 {
		flowBatchSize = defaultFlowBatchSize
	}
	slog.Debug("flow map iteration start")
	keysBatch := make([][flowKeySize]byte, flowBatchSize)
	valuesBatch := make([]types.FlowValue, flowBatchSize*possibleCPUs)
	var cursor ebpf.MapBatchCursor
	keysThisPoll := 0

	mapReadStart := time.Now()
	for {
		if ctx.Err() != nil {
			break
		}
		n, batchErr := c.objs.FlowMap.BatchLookup(&cursor, keysBatch, valuesBatch, nil)
		if batchErr != nil && !errors.Is(batchErr, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("flow map batch lookup failed (requires kernel 6.6+): %w", batchErr)
		}
		if n == 0 {
			break
		}
		for i := 0; i < n; i++ {
			addFlowToCurrent(keysBatch[i][:], valuesBatch[i*possibleCPUs:(i+1)*possibleCPUs], current, now)
		}
		keysThisPoll += n
		if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
			break
		}
	}

	mapReadDuration := time.Since(mapReadStart).Seconds()
	c.metrics.mapReadDurationSeconds.Set(mapReadDuration)
	slog.Debug("flow map iteration done", "keys_iterated", keysThisPoll, "flows_collected", len(current), "duration_sec", mapReadDuration)

	// Pre-fetch interface names to avoid nested locking
	uniqueIfindexes := make(map[int]struct{})
	for k := range current {
		uniqueIfindexes[int(k.Ifindex)] = struct{}{}
	}
	ifNames := make(map[int]string, len(uniqueIfindexes))
	for ifindex := range uniqueIfindexes {
		ifNames[ifindex] = c.getIfName(ifindex)
	}

	c.shadowMu.Lock()
	defer c.shadowMu.Unlock()

	evictionMinAgeSec := math.MaxFloat64
	for k, prev := range c.shadow {
		if _, in := current[k]; !in {
			ageSec := now.Sub(prev.LastPollAt).Seconds()
			if ageSec < evictionMinAgeSec {
				evictionMinAgeSec = ageSec
			}
			delete(c.shadow, k)
			delete(c.countryCache, k)
		}
	}

	for k, cur := range current {
		prev, had := c.shadow[k]
		var deltaBytes uint64
		if had {
			if cur.Bytes >= prev.Bytes && cur.Packets >= prev.Packets {
				deltaBytes = cur.Bytes - prev.Bytes
			} else {
				deltaBytes = cur.Bytes
			}
		} else {
			deltaBytes = cur.Bytes
		}
		c.shadow[k] = cur

		// Reconstruct /32 (v4) or /128 (v6) by zero-padding the prefix for GeoIP lookup.
		ifName := ifNames[int(k.Ifindex)] // Use pre-fetched name (no nested lock)
		dirStr := "RX"
		if k.Dir == types.DirTX {
			dirStr = "TX"
		}
		flowDesc := dirStr + " " + ifName
		country := "UNKNOWN"
		if c.geo != nil {
			if cached, ok := c.countryCache[k]; ok {
				country = cached
			} else {
				if k.IpVersion == 4 {
					var addr [4]byte
					copy(addr[:], k.Addr[:3])
					addr[3] = 0
					country = c.geo.LookupV4(addr, flowDesc)
				} else if k.IpVersion == 6 {
					var addr [16]byte
					copy(addr[:6], k.Addr[:6])
					country = c.geo.LookupV6(addr, flowDesc)
				}
				c.countryCache[k] = country
			}
		}
		var ipVer string
		switch k.IpVersion {
		case 4:
			ipVer = "4"
		case 6:
			ipVer = "6"
		default:
			ipVer = "?"
		}
		if k.Dir == types.DirRX {
			c.metrics.bytesReceived.WithLabelValues(country, ifName, ipVer).Add(float64(deltaBytes))
		} else {
			c.metrics.bytesSent.WithLabelValues(country, ifName, ipVer).Add(float64(deltaBytes))
		}
	}

	c.metrics.mapEntries.Set(float64(len(current)))
	// Only update the metric when evictions actually occurred in this poll
	// This makes the metric "sticky" - it retains the last known value
	if evictionMinAgeSec < math.MaxFloat64 {
		c.lastMinEvictionAgeSec = evictionMinAgeSec
		c.metrics.evictionMinAgeSeconds.Set(evictionMinAgeSec)
	}
	// If no evictions this poll, lastMinEvictionAgeSec and the metric retain their previous values

	sums, _ := c.readStats()
	slog.Debug("readStats", "packets_seen", sums[types.StatPacketsSeen], "lookup_fail", sums[types.StatLookupFail], "update_fail", sums[types.StatUpdateFail], "new_keys", sums[types.StatNewKeys], "evictions", sums[types.StatEvictionPressure])
	slog.Debug("poll done", "flows", len(current), "packets_seen", sums[types.StatPacketsSeen], "lookup_fail", sums[types.StatLookupFail], "evictions", sums[types.StatEvictionPressure])
	return nil
}

func (c *Collector) readStats() ([types.NumStats]uint64, error) {
	var sums [types.NumStats]uint64
	for i := 0; i < types.NumStats; i++ {
		key := uint32(i)
		var values []uint64
		if err := c.objs.StatsMap.Lookup(&key, &values); err != nil {
			continue
		}
		for _, v := range values {
			sums[i] += v
		}
	}
	for i := 0; i < types.NumStats; i++ {
		if sums[i] >= c.prevStats[i] {
			delta := sums[i] - c.prevStats[i]
			switch i {
			case types.StatPacketsSeen:
				c.metrics.packetsTotal.Add(float64(delta))
			case types.StatLookupFail:
				c.metrics.lookupFailTotal.Add(float64(delta))
			case types.StatUpdateFail:
				c.metrics.updateFailTotal.Add(float64(delta))
			case types.StatNewKeys:
				c.metrics.newKeysTotal.Add(float64(delta))
			case types.StatEvictionPressure:
				c.metrics.evictionsTotal.Add(float64(delta))
			}
		}
		c.prevStats[i] = sums[i]
	}
	return sums, nil
}

func interfaceNames(interfaces []net.Interface) []string {
	names := make([]string, len(interfaces))
	for i := range interfaces {
		names[i] = stableInterfaceName(interfaces[i]) + " (index " + fmt.Sprint(interfaces[i].Index) + ")"
	}
	return names
}

func stableInterfaceName(iface net.Interface) string {
	if iface.Name != "" {
		return iface.Name
	}
	return fmt.Sprintf("%d", iface.Index)
}

// checkKernelVersion verifies kernel is 6.6+ (required for TCX bpf_link).
func checkKernelVersion() error {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return fmt.Errorf("failed to get kernel version: %w", err)
	}
	release := string(uname.Release[:bytes.IndexByte(uname.Release[:], 0)])

	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return fmt.Errorf("kernel version %q: invalid format (expected X.Y.Z)", release)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("kernel version %q: invalid major version", release)
	}

	minorStr := parts[1]
	// Strip anything after first non-digit (e.g., "12+deb13" -> "12")
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}
	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return fmt.Errorf("kernel version %q: invalid minor version", release)
	}

	if major < 6 || (major == 6 && minor < 6) {
		return fmt.Errorf("kernel %d.%d (from %q): TCX requires kernel 6.6 or newer", major, minor, release)
	}

	slog.Info("kernel version check passed", "version", release, "major", major, "minor", minor)
	return nil
}
