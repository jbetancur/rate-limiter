//go:build ignore

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The limit of packets within a given rate
#ifndef PACKET_LIMIT
#define PACKET_LIMIT 10000
#endif

// The rate limit in packets per second
// RATELIMIT = PACKET_LIMIT / RATE
#ifndef RATE
#define RATE 5
#endif

#ifndef MAX_MAP_ENTRIES
#define MAX_MAP_ENTRIES 500
#endif

#define NS_IN_SEC 1000000000LL

struct bpf_elf_map {
	__u32	type;
	__u32	key_size;
	__u32	value_size;
	__u32	max_elem;
	__u32	flags;
};

struct packet_state {
	__u32	tokens;
	__u64	timestamp;
	_Bool 	rate_limited;
	__u64	pkt_drop_counter;
	__u64	config_limit;
	__u64 	config_rate;
	__u64   actual_rate_limit;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") source_ip_mapping = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32), // Assuming IPv4 addresses
	.value_size = sizeof(struct packet_state),
	.max_elem = MAX_MAP_ENTRIES,
};

/*
Attempt to parse the IPv4 source address from the packet.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md* ctx, __u32* ip_src_addr) {
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr* eth = data;
	if ((void*)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}

	// Then parse the IP header.
	struct iphdr* ip = (void*)(eth + 1);
	if ((void*)(ip + 1) > data_end) {
		return 0;
	}

	// Return the source IP address in network byte order.
	*ip_src_addr = (__u32)(ip->saddr);

	return 1;
}

SEC("xdp")
int rate_limit(struct xdp_md* ctx)
{
	struct  packet_state* elem, entry = { 0 };
	__u64   now;
	__u32 source_ip;

	if (!parse_ip_src_addr(ctx, &source_ip)) {
		// Not an IPv4 packet, so don't count it.
		goto done;
	}

	elem = bpf_map_lookup_elem(&source_ip_mapping, &source_ip);

	if (elem == NULL) {
		entry.tokens = PACKET_LIMIT;
		entry.timestamp = bpf_ktime_get_ns();
		entry.rate_limited = 0;
		entry.config_limit = PACKET_LIMIT;
		entry.config_rate = RATE;
		entry.actual_rate_limit = PACKET_LIMIT / RATE; // Calculate and store the static rate limit

		bpf_map_update_elem(&source_ip_mapping, &source_ip, &entry, BPF_ANY);
	}
	else {
		if (elem->tokens == 0) {
			now = bpf_ktime_get_ns();

			// If the elapsed time from the last packet exceeds the Rate per second, refill the bucket with tokens
			if (now - elem->timestamp > (NS_IN_SEC * RATE)) {
				elem->timestamp = now;
				elem->tokens = PACKET_LIMIT;
				// Reset when tokens are refilled (no longer rate limited)
				elem->pkt_drop_counter = 0;
				elem->rate_limited = 0;
			}
			else {
				elem->pkt_drop_counter++;
				elem->rate_limited = 1;

				return XDP_DROP;
			}
		}

		elem->tokens--;

		// Update the rate limit in real-time if it changes via config
		elem->actual_rate_limit = elem->config_limit / elem->config_rate;
	}

done:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";