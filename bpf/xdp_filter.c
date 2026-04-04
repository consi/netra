// Minimal XDP program: redirect UDP packets on a configurable port to AF_XDP socket,
// pass everything else. Port is set via the target_port BPF map from userspace.
// Self-contained — no libbpf/bpf_helpers.h dependency.
// Compiled with: clang -target bpf -O2 -I/usr/include/x86_64-linux-gnu -c xdp_filter.c -o xdp_filter.o

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef __u16 __be16;

#define SEC(name) __attribute__((section(name), used))
#define XDP_PASS 2

// BPF map definition using BTF-style struct
struct {
    int (*type)[17];           // BPF_MAP_TYPE_XSKMAP = 17
    int (*key_size)[4];        // sizeof(int)
    int (*value_size)[4];      // sizeof(int)
    int (*max_entries)[64];
} xsks_map SEC(".maps");

// BPF_MAP_TYPE_ARRAY with a single entry holding the target UDP port.
// Userspace writes the port after loading the program.
// Default value is 0; if not set, falls back to 2055.
struct {
    int (*type)[2];            // BPF_MAP_TYPE_ARRAY = 2
    int (*key_size)[4];        // sizeof(__u32)
    int (*value_size)[2];      // sizeof(__u16)
    int (*max_entries)[1];
} target_port SEC(".maps");

// BPF helper: bpf_redirect_map (helper #51)
static long (*bpf_redirect_map)(void *map, __u32 key, __u64 flags) = (void *)51;
// BPF helper: bpf_map_lookup_elem (helper #1)
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

// Ethernet header (14 bytes)
struct ethhdr {
    __u8 h_dest[6];
    __u8 h_source[6];
    __be16 h_proto;
};

// IPv4 header (simplified, minimum 20 bytes)
struct iphdr {
    __u8 ihl_ver;    // version:4, ihl:4
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __be16 check;
    __u32 saddr;
    __u32 daddr;
};

// IPv6 header (40 bytes)
struct ipv6hdr {
    __u32 flow;
    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;
    __u8 saddr[16];
    __u8 daddr[16];
};

// UDP header (8 bytes)
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __be16 check;
};

// XDP metadata
struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

static inline __attribute__((always_inline)) __u16 bswap16(__be16 x) {
    return __builtin_bswap16(x);
}

#define ETH_P_IP    0x0800
#define ETH_P_IPV6  0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8
#define IPPROTO_UDP 17

SEC("xdp")
int xdp_redirect_udp2055(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = bswap16(eth->h_proto);
    void *next = (void *)(eth + 1);

    // Skip single VLAN tag (802.1Q / 802.1AD)
    if (h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD) {
        struct {
            __be16 tci;
            __be16 inner_proto;
        } *vhdr = next;
        if ((void *)(vhdr + 1) > data_end)
            return XDP_PASS;
        h_proto = bswap16(vhdr->inner_proto);
        next = (void *)(vhdr + 1);
    }

    __u8 ip_proto;
    if (h_proto == ETH_P_IP) {
        struct iphdr *ip = next;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        ip_proto = ip->protocol;
        // Advance past IP header (variable IHL)
        __u8 ihl = ip->ihl_ver & 0x0F;
        next = (void *)ip + ihl * 4;
        if (next > data_end)
            return XDP_PASS;
    } else if (h_proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = next;
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        ip_proto = ip6->nexthdr;
        next = (void *)(ip6 + 1);
    } else {
        return XDP_PASS;
    }

    if (ip_proto != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = next;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    // Read configured port from map, default to 2055 if not set
    __u32 key = 0;
    __u16 *port_val = bpf_map_lookup_elem(&target_port, &key);
    __u16 port = (port_val && *port_val) ? *port_val : 2055;
    if (bswap16(udp->dest) != port)
        return XDP_PASS;

    // Redirect to AF_XDP socket for this RX queue
    return bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);
}

char _license[] SEC("license") = "Dual MIT/GPL";
