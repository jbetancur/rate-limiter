//go:build ignore

#include <stdint.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef PACKET_LIMIT
#define PACKET_LIMIT 10000
#endif

#ifndef RATE
#define RATE 5
#endif

#ifndef MAX_MAP_ENTRIES
#define MAX_MAP_ENTRIES 65536
#endif

#define NS_IN_SEC 1000000000LL

#define bpf_printk(fmt, ...)                             \
({                                                       \
    char ____fmt[] = fmt;                                \
    bpf_trace_printk(____fmt, sizeof(____fmt),           \
    ##__VA_ARGS__);                     \
})

struct port_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding; // Padding for alignment
};

struct bpf_elf_map {
    __u32 type;
    __u32 key_size;
    __u32 value_size;
    __u32 max_elem;
    __u32 flags;
};

struct packet_state {
    __u32 tokens;
    __u64 last_refill;
    _Bool rate_limited;
    __u64 pkt_drop_counter;
    __u64 config_limit;
    __u64 config_rate;
    __u64 actual_rate_limit;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") connections = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = sizeof(struct packet_state),
    .max_elem = MAX_MAP_ENTRIES,
};

struct metrics {
    __u32 src_ip;
    __u16 src_port;
    __u64 pkt_drop_counter;
    __u64 pkt_count;
    __u64 last_refill;
};

struct bpf_elf_map SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_elem = 0,
};

struct cidr_key {
    __u32 network;  // Network part of the IP
    __u32 prefix_len; // Prefix length
} __attribute__((packed));

// Map to store CIDR ranges for exclusion
struct bpf_elf_map SEC("maps") cidr_exclusions = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct cidr_key),
    .value_size = sizeof(__u32),
    .max_elem = 256,
};

// Function to parse packet headers
static __always_inline int parse_packet_headers(struct xdp_md* ctx, __u16* src_port, __u32* src_ip) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr* eth = data;

    // Parse the ethernet header.
    if ((void*)(eth + 1) > data_end) {
        return 0;
    }

    // The protocol is not IPv4, so we can't parse an IPv4 source address.
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return 0;
    }

    struct iphdr* ip = (struct iphdr*)(eth + 1);
    if ((void*)(ip + 1) > data_end) {
        return 0;
    }

    *src_ip = ip->saddr;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = (struct tcphdr*)(ip + 1);

        if ((void*)(tcp + 1) > data_end) {
            return 0;
        }

        *src_port = bpf_ntohs(tcp->source);
    }
    else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(ip + 1);

        if ((void*)(udp + 1) > data_end) {
            return 0;
        }

        *src_port = bpf_ntohs(udp->source);
    }
    else {
        return 0;
    }

    return 1;
}

// Check if IP is in any exclusion range
static __always_inline _Bool is_in_exclusion_list(__u32 ip) {
    struct cidr_key key = { 0 };
    __u32 mask = 0;
    __u32* value;

    for (int i = 0; i <= 32; i++) {
        key.network = ip & bpf_htonl(mask);
        key.prefix_len = i;
        value = bpf_map_lookup_elem(&cidr_exclusions, &key);
        if (value) {
            return 1;
        }
        mask = (mask >> 1) | 0x80000000;
    }

    return 0;
}

// Initialize a new packet state map
static __always_inline void init_packet_state(struct packet_state* state) {
    state->tokens = PACKET_LIMIT;
    state->last_refill = bpf_ktime_get_ns();
    state->rate_limited = 0;
    state->config_limit = PACKET_LIMIT;
    state->config_rate = RATE;
    state->actual_rate_limit = PACKET_LIMIT / RATE;
    state->pkt_drop_counter = 0;
}

// Function to add tokens based on elapsed time
static __always_inline void add_tokens(struct packet_state* state, __u64 now) {
    __u64 elapsed_time_ns = now - state->last_refill;

    // Calculate the number of tokens to add based on the elapsed nanoseconds
    // elapsed_time_ns (nanoseconds)
    // state->config_rate (tokens/second)
    // NS_IN_SEC (nanoseconds/second)
    // For example, if elapsed_time_ns is 5000000000 nanoseconds (5 seconds) and state->config_rate is 10 tokens/second:
    // tokens_to_add = (5000000000 * 10) / 1000000000
    // tokens_to_add = 50000000000 / 1000000000
    // tokens_to_add = 50    
    __u64 tokens_to_add = (elapsed_time_ns * state->config_rate) / NS_IN_SEC;

    bpf_printk("toadd: %d", tokens_to_add);

    if (tokens_to_add > 0) {
        state->tokens = (state->tokens + tokens_to_add > state->config_limit) ? state->config_limit : state->tokens + tokens_to_add;
        state->last_refill = now; // Update last refill to the current time
    }
}

static __always_inline int handle_rate_limit(struct xdp_md* ctx, struct packet_state* state, struct port_key* key) {
    struct metrics metric = { 0 };
    __u64 now = bpf_ktime_get_ns();

    // Add tokens to the bucket
    add_tokens(state, now);

    // Check if there are enough tokens to pass the packet
    if (state->tokens > 0) {
        state->tokens--;
        state->rate_limited = 0;

        // Send metrics to user-space even when not rate limited
        metric.src_ip = key->src_ip;
        metric.src_port = key->src_port;
        metric.pkt_drop_counter = state->pkt_drop_counter;
        metric.last_refill = state->last_refill;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &metric, sizeof(metric));

        return XDP_PASS;
    }

    state->pkt_drop_counter++;
    state->rate_limited = 1;

    // Collect and send metrics to user-space
    metric.src_ip = key->src_ip;
    metric.src_port = key->src_port;
    metric.pkt_drop_counter = state->pkt_drop_counter;
    metric.last_refill = state->last_refill;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &metric, sizeof(metric));

    return XDP_DROP;
}


SEC("xdp")
int rate_limit(struct xdp_md* ctx) {
    struct port_key key = { 0 };
    struct packet_state* state;
    struct packet_state new_state;

    // Check if this is a valid packet and if so set attributes
    if (!parse_packet_headers(ctx, &key.src_port, &key.src_ip)) {
        return XDP_PASS;
    }

    // Check if IP is in exclusion list
    if (is_in_exclusion_list(key.src_ip)) {
        return XDP_PASS;
    }

    state = bpf_map_lookup_elem(&connections, &key);

    if (!state) {
        init_packet_state(&new_state);
        bpf_map_update_elem(&connections, &key, &new_state, BPF_ANY);
        state = bpf_map_lookup_elem(&connections, &key);

        if (!state) {
            return XDP_PASS; // Shouldn't happen, but safe check
        }
    }

    // Handle rate limiting
    return handle_rate_limit(ctx, state, &key);
}

char _license[] SEC("license") = "GPL";
