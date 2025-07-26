#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>

#define DEFAULT_PORT 4040
#define STATS_TOTAL_PACKETS 0
#define STATS_DROPPED_PACKETS 1

static int port_map_fd = -1;
static int stats_map_fd = -1;
static int prog_fd = -1;
static int ifindex = -1;
static struct bpf_link *xdp_link = NULL;

static void cleanup(int sig __attribute__((unused)))
{
    printf("\nCleaning up...\n");
    
    if (xdp_link) {
        bpf_link__destroy(xdp_link);
        printf("XDP program detached successfully\n");
    }
    
    exit(0);
}

static void print_stats()
{
    __u32 key;
    __u64 value;
    
    key = STATS_TOTAL_PACKETS;
    if (bpf_map_lookup_elem(stats_map_fd, &key, &value) == 0) {
        printf("Total TCP packets processed: %llu\n", value);
    }
    
    key = STATS_DROPPED_PACKETS;
    if (bpf_map_lookup_elem(stats_map_fd, &key, &value) == 0) {
        printf("TCP packets dropped: %llu\n", value);
    }
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *port_map, *stats_map;
    int err;
    char *ifname = "eth0"; // Default interface
    __u16 drop_port = DEFAULT_PORT;
    
    // Parse command line arguments
    if (argc > 1) {
        ifname = argv[1];
    }
    if (argc > 2) {
        drop_port = atoi(argv[2]);
        if (drop_port == 0) {
            fprintf(stderr, "Invalid port number: %s\n", argv[2]);
            return 1;
        }
    }
    
    printf("TCP Port Dropper - eBPF XDP Program\n");
    printf("Interface: %s\n", ifname);
    printf("Dropping TCP packets on port: %d\n", drop_port);
    printf("Press Ctrl+C to stop and view statistics...\n\n");
    
    // Set up signal handler
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    
    // Increase RLIMIT_MEMLOCK to allow eBPF
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        perror("setrlimit");
        return 1;
    }
    
    // Get interface index
    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", 
                ifname, strerror(errno));
        return 1;
    }
    
    // Load eBPF object file
    obj = bpf_object__open_file("tcp_drop_kern.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Failed to open BPF object file: %s\n", strerror(-err));
        return 1;
    }
    
    // Load eBPF program
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    // Find the XDP program
    prog = bpf_object__find_program_by_name(obj, "xdp_tcp_drop");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Failed to get program fd\n");
        bpf_object__close(obj);
        return 1;
    }
    
    // Find maps
    port_map = bpf_object__find_map_by_name(obj, "port_map");
    if (!port_map) {
        fprintf(stderr, "Failed to find port_map\n");
        bpf_object__close(obj);
        return 1;
    }
    
    stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!stats_map) {
        fprintf(stderr, "Failed to find stats_map\n");
        bpf_object__close(obj);
        return 1;
    }
    
    port_map_fd = bpf_map__fd(port_map);
    stats_map_fd = bpf_map__fd(stats_map);
    
    // Configure the port to drop
    __u32 key = 0;
    err = bpf_map_update_elem(port_map_fd, &key, &drop_port, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update port map: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    // Initialize statistics
    __u64 zero = 0;
    key = STATS_TOTAL_PACKETS;
    bpf_map_update_elem(stats_map_fd, &key, &zero, BPF_ANY);
    key = STATS_DROPPED_PACKETS;
    bpf_map_update_elem(stats_map_fd, &key, &zero, BPF_ANY);
    
    // Attach XDP program to interface using modern API
    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if (!xdp_link) {
        err = -errno;
        fprintf(stderr, "Failed to attach XDP program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    printf("XDP program loaded and attached successfully!\n");
    printf("Monitoring traffic... (Press Ctrl+C to stop)\n\n");
    
    // Print statistics every 5 seconds
    while (1) {
        sleep(5);
        print_stats();
        printf("\n");
    }
    
    // Cleanup (though this won't be reached due to infinite loop)
    if (xdp_link) {
        bpf_link__destroy(xdp_link);
    }
    bpf_object__close(obj);
    
    return 0;
}
