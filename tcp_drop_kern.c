#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Map to store the port number to drop (configurable from userspace)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_map SEC(".maps");

// Map to store packet statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#define STATS_TOTAL_PACKETS 0
#define STATS_DROPPED_PACKETS 1

SEC("xdp")
int xdp_tcp_drop(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's an IPv4 packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    
    // Update total packet count
    __u32 stats_key = STATS_TOTAL_PACKETS;
    __u64 *total_count = bpf_map_lookup_elem(&stats_map, &stats_key);
    if (total_count)
        __sync_fetch_and_add(total_count, 1);
    
    // Get the configured port to drop
    __u32 port_key = 0;
    __u16 *drop_port = bpf_map_lookup_elem(&port_map, &port_key);
    if (!drop_port)
        return XDP_PASS; // If no port configured, pass all packets
    
    // Check if this packet matches the port to drop
    __u16 dest_port = bpf_ntohs(tcp->dest);
    __u16 src_port = bpf_ntohs(tcp->source);
    
    if (dest_port == *drop_port || src_port == *drop_port) {
        // Update dropped packet count
        stats_key = STATS_DROPPED_PACKETS;
        __u64 *drop_count = bpf_map_lookup_elem(&stats_map, &stats_key);
        if (drop_count)
            __sync_fetch_and_add(drop_count, 1);
        
        // Log the drop action (optional)
        bpf_printk("Dropping TCP packet on port %d\n", *drop_port);
        
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
