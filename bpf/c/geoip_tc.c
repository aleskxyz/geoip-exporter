// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* GeoIP traffic accounting - TC ingress/egress aggregation.
 * Kernel maintains per-flow packets/bytes; userspace does delta + GeoIP.
 * Key: 24-bit prefix for IPv4, 48-bit prefix for IPv6 (saves space, fixes padding).
 */

#ifndef __BPF_TRACING__
#define __BPF_TRACING__
#endif

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DIR_RX 0
#define DIR_TX 1

#define STAT_PACKETS_SEEN    0
#define STAT_LOOKUP_FAIL     1
#define STAT_UPDATE_FAIL     2
#define STAT_IPV4_PACKETS    3
#define STAT_IPV6_PACKETS    4
#define STAT_NEW_KEYS        5
#define STAT_EVICTION_PRESSURE 6

/* addr: IPv4 = first 24 bits (3 bytes MSB); IPv6 = first 48 bits (6 bytes) */
struct flow_key {
	__u8  ip_version; /* 4 or 6 */
	__u8  dir;        /* RX=0, TX=1 */
	__u32 ifindex;
	__u8  addr[6];
};

struct flow_value {
	__u64 packets;
	__u64 bytes;
	__u64 last_seen_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__type(key, struct flow_key);
	__type(value, struct flow_value);
	__uint(max_entries, 1000000); /* overridden by userspace */
} flow_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 7);
	__type(key, __u32);
	__type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
	__u32 key = idx;
	__u64 *val = bpf_map_lookup_elem(&stats_map, &key);
	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
}

static __always_inline int parse_ipv4(void *data, void *data_end, __u32 *saddr, __u32 *daddr)
{
	struct iphdr *iph = (struct iphdr *)data;
	if ((void *)(iph + 1) > data_end)
		return -1;
	if (iph->ihl < 5)
		return -1;
	*saddr = iph->saddr;
	*daddr = iph->daddr;
	return 0;
}

static __always_inline int parse_ipv6(void *data, void *data_end, __u8 saddr[16], __u8 daddr[16])
{
	struct ipv6hdr *ip6 = (struct ipv6hdr *)data;
	if ((void *)(ip6 + 1) > data_end)
		return -1;
	__builtin_memcpy(saddr, &ip6->saddr, 16);
	__builtin_memcpy(daddr, &ip6->daddr, 16);
	return 0;
}

/* Store first 24 bits of IPv4 (MSB) into key.addr[0..2] */
static __always_inline void key_set_v4_prefix(__u8 *addr, __u32 v4)
{
	addr[0] = (v4 >> 24) & 0xff;
	addr[1] = (v4 >> 16) & 0xff;
	addr[2] = (v4 >> 8) & 0xff;
}

static __always_inline int process_flow(struct flow_key *key, __u64 len)
{
	struct flow_value zero = {}, *val;
	__u64 now = bpf_ktime_get_ns();

	val = bpf_map_lookup_elem(&flow_map, key);
	if (!val) {
		zero.packets = 1;
		zero.bytes = len;
		zero.last_seen_ns = now;
		if (bpf_map_update_elem(&flow_map, key, &zero, BPF_NOEXIST) != 0) {
			val = bpf_map_lookup_elem(&flow_map, key);
			if (!val) {
				inc_stat(STAT_LOOKUP_FAIL);
				inc_stat(STAT_UPDATE_FAIL);
				return -1;
			}
			val->packets += 1;
			val->bytes += len;
			val->last_seen_ns = now;
			return 0;
		}
		inc_stat(STAT_NEW_KEYS);
		return 0;
	}
	val->packets += 1;
	val->bytes += len;
	val->last_seen_ns = now;
	return 0;
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 dir)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 ifindex = skb->ifindex;
	__u64 len = skb->len;
	__u16 proto;

	inc_stat(STAT_PACKETS_SEEN);

	if (data + sizeof(struct ethhdr) > data_end)
		return 0;
	proto = ((struct ethhdr *)data)->h_proto;
	if (proto != bpf_htons(ETH_P_IP) && proto != bpf_htons(ETH_P_IPV6))
		return 0;

	if (proto == bpf_htons(ETH_P_IP)) {
		__u32 saddr, daddr;
		struct flow_key key = {
			.ip_version = 4,
			.dir = dir,
			.ifindex = ifindex,
		};
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
			return 0;
		if (parse_ipv4(data + sizeof(struct ethhdr), data_end, &saddr, &daddr) != 0)
			return 0;
		inc_stat(STAT_IPV4_PACKETS);
		key_set_v4_prefix(key.addr, bpf_ntohl(dir == DIR_RX ? saddr : daddr));
		if (process_flow(&key, len) != 0)
			inc_stat(STAT_LOOKUP_FAIL);
	} else {
		__u8 saddr[16], daddr[16];
		struct flow_key key = {
			.ip_version = 6,
			.dir = dir,
			.ifindex = ifindex,
		};
		if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > data_end)
			return 0;
		if (parse_ipv6(data + sizeof(struct ethhdr), data_end, saddr, daddr) != 0)
			return 0;
		inc_stat(STAT_IPV6_PACKETS);
		__builtin_memcpy(key.addr, dir == DIR_RX ? saddr : daddr, 6);
		if (process_flow(&key, len) != 0)
			inc_stat(STAT_LOOKUP_FAIL);
	}
	return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
	return process_packet(skb, DIR_RX);
}

SEC("tc")
int tc_egress(struct __sk_buff *skb)
{
	return process_packet(skb, DIR_TX);
}

char _license[] SEC("license") = "GPL";
