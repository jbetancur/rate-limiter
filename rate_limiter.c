//go:build ignore

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef PACKET_LIMIT
#define PACKET_LIMIT 50000
#endif

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
	__u32 	pkt_counter;
	__u32	pkt_drop_counter;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") source_ip_mapping = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32), // Assuming IPv4 addresses
	.value_size = sizeof(struct packet_state),
	.max_elem = MAX_MAP_ENTRIES,
};

// struct bpf_elf_map SEC("maps") config_map = {
// 	.type = BPF_MAP_TYPE_HASH,
// 	.key_size = sizeof(char),
// 	.value_size = sizeof(__u32),
// 	.max_elem = 2, // Assuming only two config values: PACKET_LIMIT and PACKET_RATE
// };

/*
Attempt to parse the IPv4 source address from the packet.
*/
static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	// First, parse the ethernet header.
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		return 0;
	}

	if (eth->h_proto != bpf_htons(ETH_P_IP)) {
		// The protocol is not IPv4, so we can't parse an IPv4 source address.
		return 0;
	}
  
	// Then parse the IP header.
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) {
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
		entry.pkt_counter = 1;

		bpf_map_update_elem(&source_ip_mapping, &source_ip, &entry, BPF_ANY);
	}
	else {
		if (elem->tokens == 0) {
			now = bpf_ktime_get_ns();

			if (now - elem->timestamp > (NS_IN_SEC * RATE)) {
				elem->timestamp = now;
				elem->tokens = PACKET_LIMIT;
			}
			else {
				elem->pkt_drop_counter++;

				return XDP_DROP;
			}
		}

		elem->tokens--;
		elem->pkt_counter++;
	}

done:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";