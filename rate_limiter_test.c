//go:build ignore

#include <rate-limiter.c>
#include <gtest/gtest.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// Mocking XDP context and required functions
struct xdp_md {
    void* data;
    void* data_end;
};

__u16 bpf_htons(__u16 val) {
    return val;
}

__u64 bpf_ktime_get_ns() {
    return 0; // Mocked time
}

#include "your_program.c" // Include your program file

// Test case for the rate_limit function
TEST(RateLimitTest, RateLimitTest) {
    struct xdp_md ctx;
    struct ethhdr eth;
    struct iphdr ip;

    // Prepare the packet with IPv4 header
    ctx.data = &eth;
    ctx.data_end = &ip + 1;
    eth.h_proto = bpf_htons(ETH_P_IP);
    ip.saddr = bpf_htonl(INADDR_LOOPBACK); // Set source IP to loopback address

    // Run the function
    int result = rate_limit(&ctx);

    // Assert that the function returns XDP_PASS for a valid IPv4 packet
    ASSERT_EQ(result, XDP_PASS);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
