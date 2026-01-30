# GeoIP Exporter for Prometheus

High-performance GeoIP network traffic accounting using eBPF kernel aggregation and a Go userspace collector. Tracks total bytes sent and received **per interface, per IP version, per country**. Exports Prometheus metrics. For monitoring only; counters are approximate under LRU eviction.

## Architecture

```
TC ingress + egress (eBPF)
    ↓
LRU per-CPU aggregation map
    ↓
userspace delta accounting every 1s
    ↓
GeoIP aggregation (MaxMind GeoLite2-Country)
    ↓
Prometheus exporter
```

- **TC hooks**: ingress = RX, egress = TX; attached via bpf_link (TCX, kernel 6.6+); auto-detach on process exit.
- **Kernel**: LRU per-CPU hash keyed by (ip_version, dir, ifindex, addr_prefix): IPv4 = first 24 bits, IPv6 = first 48 bits; value = packets, bytes, last_seen_ns only (no full IP sent to userspace). Internal stats in a per-CPU array.
- **Userspace**: Shadow map + delta accounting; monotonic counters; eviction detection; GeoIP with LRU cache; Prometheus `/metrics`.

## Requirements

- Linux kernel **6.6 or newer** (TCX bpf_link; no fallback for older kernels).
- Root or `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON` to load eBPF and attach TC.
- MaxMind **GeoLite2-Country** (optional): place at `/usr/share/GeoIP/GeoLite2-Country.mmdb` or set `--geoip-db`. You can download the database for free from https://git.io/GeoLite2-Country.mmdb .
- Build: Go 1.21+, clang, and kernel headers (e.g. `linux-headers-$(uname -r)`).

## Build

```bash
# Build binary (regenerates eBPF code for amd64+arm64)
make build
```

Or manually:

```bash
# Regenerate eBPF code for all architectures (requires clang and kernel headers)
make generate-ebpf-all
# Or for single architecture
make generate-ebpf ARCH=amd64

# Build binary
go build -o geoip-exporter ./cmd/geoip-exporter
```

## Usage

```bash
sudo ./geoip-exporter [options]
```

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--interfaces` | string | `any` | Comma-separated interface names; `any` = all non-loopback (including down) |
| `--geoip-db` | string | `/usr/share/GeoIP/GeoLite2-Country.mmdb` | MaxMind GeoLite2-Country path |
| `--map-max-entries` | int | 100000 | eBPF LRU map max entries |
| `--poll-interval` | duration | 2s | Interval to read kernel map and update metrics |
| `--log-level` | string | info | debug, info, warn, error |
| `--listen-address` | string | 0.0.0.0:9100 | HTTP server for /metrics |
| `--metrics-path` | string | /metrics | HTTP path for Prometheus |
| `--flow-batch-size` | int | 10000 | Keys per batch lookup syscall |
| `--geoip-cache-size` | int | 65536 | GeoIP LRU cache size (prefix → country) |

## Docker Usage

Download the GeoIP database first:

```bash
curl -L https://git.io/GeoLite2-Country.mmdb -o ./GeoLite2-Country.mmdb
```

### Option 1: Docker Compose (Recommended)

```yaml
services:
  geoip-exporter:
    build: .  # Or use: image: ghcr.io/aleskxyz/geoip-exporter:latest
    image: geoip-exporter:latest
    container_name: geoip-exporter
    network_mode: host
    cap_add:
      - CAP_BPF
      - CAP_NET_ADMIN
      - CAP_PERFMON
    volumes:
      - ./GeoLite2-Country.mmdb:/usr/share/GeoIP/GeoLite2-Country.mmdb:ro
    command:
      - --interfaces=any
      - --log-level=info
    restart: unless-stopped
```

Start:

```bash
docker compose up -d
```

### Option 2: Docker CLI

Build locally:

```bash
docker build -t geoip-exporter:latest .
docker run -d --name geoip-exporter --network=host \
  --cap-add CAP_BPF --cap-add CAP_NET_ADMIN --cap-add CAP_PERFMON \
  -v ./GeoLite2-Country.mmdb:/usr/share/GeoIP/GeoLite2-Country.mmdb:ro \
  geoip-exporter:latest --interfaces any
```

Or use pre-built image:

```bash
docker run -d --name geoip-exporter --network=host \
  --cap-add CAP_BPF --cap-add CAP_NET_ADMIN --cap-add CAP_PERFMON \
  -v ./GeoLite2-Country.mmdb:/usr/share/GeoIP/GeoLite2-Country.mmdb:ro \
  ghcr.io/aleskxyz/geoip-exporter:latest --interfaces any
```

**Note:** Requires `--network=host` and capabilities `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`. Alternative: use `--privileged` (less secure).

## Prometheus metrics

**Traffic (monotonic counters):**

- `geoip_bytes_received_total{country,interface,ip_version}`
- `geoip_bytes_sent_total{country,interface,ip_version}`

**Interface status:**

- `geoip_interface_status{interface}` — Gauge: `0` = up, `1` = down, `2` = not found. In explicit mode all configured names are reported; in `any` mode only existing non-loopback interfaces are reported (no `2`, labels dropped when an interface disappears).

**Configuration:**

- `geoip_config_map_max_entries` — Gauge: Configured maximum entries in the eBPF flow map (`--map-max-entries`).
- `geoip_config_poll_interval_seconds` — Gauge: Configured poll interval in seconds (`--poll-interval`).
- `geoip_config_flow_batch_size` — Gauge: Configured number of keys per batch lookup syscall (`--flow-batch-size`).

**Internal exporter:**

- `geoip_ebpf_packets_total`
- `geoip_ebpf_lookup_fail_total`
- `geoip_ebpf_update_fail_total`
- `geoip_ebpf_new_keys_total`
- `geoip_ebpf_evictions_total`
- `geoip_ebpf_map_entries`
- `geoip_ebpf_minimum_eviction_age_seconds`
- `geoip_ebpf_map_read_duration_seconds`

## Behaviour

- **Traffic metrics**: `geoip_bytes_received_total` and `geoip_bytes_sent_total` only appear in `/metrics` after at least one flow has been seen. If `geoip_ebpf_packets_total` stays 0, no packets are being seen on the monitored interface(s)—check the interface name and generate traffic (e.g. ping, curl) to verify.
- **Interface selection**: With `--interfaces=any`, the exporter attaches to all non-loopback interfaces (up or down). With an explicit list (e.g. `--interfaces=tun2,eth0`), only those names are used; the exporter can start even if a configured interface does not exist yet and will attach when it appears.
- **Interface lifecycle**: If an interface is removed from the system, TC is detached and internal state is cleaned up. Rename is not supported: if an interface is renamed (e.g. tun2 → tun3), it is treated as deleted and we detach. Traffic labels use the interface name (or ifindex if unknown).
- **Delta accounting**: Userspace never resets kernel counters; deltas are computed from a shadow map; if a key was evicted and recreated, current value is treated as delta to keep counters monotonic.
- **Eviction**: LRU eviction in kernel is expected; last packets of evicted keys can be lost. `geoip_ebpf_minimum_eviction_age_seconds` is the minimum age (in seconds) among evicted flows; it should be greater than the poll interval—if lower, recently-seen flows are being evicted (consider increasing `--map-max-entries`).
- **GeoIP**: Unknown/private → `UNKNOWN`; if the DB is missing or fails to open, all countries are `UNKNOWN` and the exporter still runs.
- **Reading the flow map**: The map lives in kernel memory; hash maps cannot be mmap’d into userspace. We use **batch lookup** (many keys per syscall); the batch API is required (kernel 6.6+).

## Monitoring healthy operation

**Critical health checks:**

```promql
# No packets seen (TC not attached or wrong interface)
geoip_ebpf_packets_total == 0

# Eviction pressure (flows evicted before next poll)
geoip_ebpf_minimum_eviction_age_seconds < geoip_config_poll_interval_seconds

# Falling behind (map read slower than poll interval)
geoip_ebpf_map_read_duration_seconds >= geoip_config_poll_interval_seconds

# Excessive evictions (map too small for traffic)
geoip_ebpf_evictions_total / geoip_config_map_max_entries > 0.1

# eBPF failures
rate(geoip_ebpf_lookup_fail_total[5m]) > 0 or rate(geoip_ebpf_update_fail_total[5m]) > 0
```

**Quick troubleshooting:**

- **No traffic counters?** Check `geoip_ebpf_packets_total` is increasing and `geoip_interface_status` shows `0` (up).
- **Eviction pressure?** Increase `--map-max-entries` if evictions are significant or eviction age < poll interval.
- **Slow reads?** Increase `--poll-interval` or `--flow-batch-size` if read duration ≥ poll interval.

## Non-goals

- No per-packet export, no sampling, no GeoIP in kernel, no perf buffers; not for billing-grade accuracy.

## License

This project is licensed under the **GNU General Public License v3.0** (GPL-3.0).

- **Userspace code** (Go): GPL-3.0
- **eBPF kernel code** (C): GPL-2.0 OR BSD-3-Clause (dual-licensed for kernel compatibility)

See [LICENSE](LICENSE) for full GPL-3.0 text and individual source file headers for eBPF code licensing.
