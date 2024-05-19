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

struct port_key {
    __u32 src_ip;
    __u16 src_port;
    __u16 padding; // Padding for alignment
};

struct bpf_elf_map {
    __u32   type;
    __u32   key_size;
    __u32   value_size;
    __u32   max_elem;
    __u32   flags;
};

struct packet_state {
    __u32   tokens;
    __u64   timestamp;
    _Bool   rate_limited;
    __u64   pkt_drop_counter;
    __u64   config_limit;
    __u64   config_rate;
    __u64   actual_rate_limit;
} __attribute__((packed));

struct bpf_elf_map SEC("maps") connections = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = sizeof(struct packet_state),
    .max_elem = MAX_MAP_ENTRIES,
};

#define bpf_printk(fmt, ...)                             \
({                                                       \
    char ____fmt[] = fmt;                                \
    bpf_trace_printk(____fmt, sizeof(____fmt),           \
    ##__VA_ARGS__);                     \
})

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
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = (struct udphdr*)(ip + 1);

        if ((void*)(udp + 1) > data_end) {
            return 0;
        }

        *src_port = bpf_ntohs(udp->source);
    } else {
        return 0;
    }

    return 1;
}

SEC("xdp")
int rate_limit(struct xdp_md* ctx)
{
    struct  packet_state* elem, entry = { 0 };
    __u64   now;
    struct port_key key = { 0 };


    if (!parse_packet_headers(ctx, &key.src_port, &key.src_ip)) {
        // Failed to parse ports, so don't count it.
        goto done;
    }


    elem = bpf_map_lookup_elem(&connections, &key);

    if (elem == NULL) {
        entry.tokens = PACKET_LIMIT;
        entry.timestamp = bpf_ktime_get_ns();
        entry.rate_limited = 0;
        entry.config_limit = PACKET_LIMIT;
        entry.config_rate = RATE;
        entry.actual_rate_limit = PACKET_LIMIT / RATE;

        bpf_map_update_elem(&connections, &key, &entry, BPF_ANY);
    }
    else {
        if (elem->tokens == 0) {
            now = bpf_ktime_get_ns();

            if (now - elem->timestamp > (NS_IN_SEC * RATE)) {
                elem->timestamp = now;
                elem->tokens = PACKET_LIMIT;
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
        elem->actual_rate_limit = elem->config_limit / elem->config_rate;
    }

done:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
