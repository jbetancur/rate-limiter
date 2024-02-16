// SPDX-License-Identifier: GPL-2.0

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

#define MAX_PACKETS 50000
#define INTERVAL 5
#define NS_IN_SEC 1000000000LL

struct bpf_elf_map {
	__u32	type;
	__u32	key_size;
	__u32	value_size;
	__u32	max_elem;
	__u32	flags;
};

struct lladdr_state {
	__u32	tokens;
	__u64	timestamp;
	__u32 	pkt_counter;
	__u32	pkt_drop_counter;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") lladdr_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u8) * ETH_ALEN,
	.value_size = sizeof(struct lladdr_state),
	.max_elem = 500,
};

#define bpf_debug(fmt, ...) \
({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
	##__VA_ARGS__); \
})


SEC("rate_limiter")
int xdp_l2_tbf(struct xdp_md* ctx)
{
	struct	lladdr_state* elem, entry = {0};
	__u64	now;
	void* data_end = (void*)(long)ctx->data_end;
	void* data = (void*)(long)ctx->data;

	bpf_debug("here !\n");

	/* we map the Ethernet header to the data pointer */
	struct ethhdr* eth = data;

	// Verify size of ethernet header
	__u64 nh_off = sizeof(*eth);
	
	if (data + nh_off > data_end) {
		bpf_debug("dropped here !\n");

		return XDP_DROP;
	}

	bpf_debug("addr: %x:%x\n",
		eth->h_source[0],
		eth->h_source[1]);

	elem = bpf_map_lookup_elem(&lladdr_map, eth->h_source);

	if (elem == NULL) {
		entry.tokens = MAX_PACKETS;
		entry.timestamp = bpf_ktime_get_ns();
		entry.pkt_counter = 1;

		bpf_map_update_elem(&lladdr_map, eth->h_source, &entry, BPF_ANY);
		bpf_debug("this element is empty\n");
	}
	else {
		bpf_debug("tokens %d\n", elem->tokens);

		if (elem->tokens == 0) {
			now = bpf_ktime_get_ns();

			if (now - elem->timestamp > (NS_IN_SEC * INTERVAL)) {
				elem->timestamp = now;
				elem->tokens = MAX_PACKETS;

				bpf_debug("now at !!!!\n");
			}
			else {
				elem->pkt_drop_counter++;

				bpf_debug("dropped !\n");
				
				return XDP_DROP;
			}
		}

		elem->tokens--;
		elem->pkt_counter++;
	}


	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";