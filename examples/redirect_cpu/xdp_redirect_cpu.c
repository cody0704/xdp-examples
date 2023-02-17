// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// #include <bpf/parse_helpers.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <bpf/hash_func01.h>

// CPUMAP
// #include <linux/kthread.h>
// #include <linux/ptr_ring.h>

#define MAX_SOCKS 64

#define MAX_CPUS 64

/* Hashing initval */
#define INITVAL 15485863

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

// static volatile unsigned const short PORT;
// static volatile unsigned const int MAX;

// Ensure map references are available.
/*
			These will be initiated from go and
			referenced in the end BPF opcodes by file descriptor
*/

/* Special map type that can XDP_REDIRECT frames to another CPU */
struct bpf_map_def SEC("maps") cpu_map = {
		.type = BPF_MAP_TYPE_CPUMAP,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_available = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = MAX_CPUS,
};

struct bpf_map_def SEC("maps") cpus_count = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = 1,
};

struct bpf_map_def SEC("maps") cpus_iterator = {
		.type = BPF_MAP_TYPE_PERCPU_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = 1,
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	__u32 key0 = 0;
	__u32 cpu_dest;
	__u32 *cpu_max;
	// __u32 *cpu_lookup;
	__u32 *cpu_selected;
	__u32 *cpu_iterator;
	__u32 cpu_idx;
	__u16 PORT = 1813;

	// int index = ctx->rx_queue_index;
	// int eth_type;

	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.

	// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	__u16 h_proto = eth->h_proto;

	if ((void *)eth + sizeof(*eth) > data_end)
		goto out;

	if (bpf_htons(h_proto) != ETH_P_IP)
		goto out;

	struct iphdr *iph = data + sizeof(*eth);

	if ((void *)iph + sizeof(*iph) > data_end)
		goto out;

	if (iph->protocol != IPPROTO_UDP)
		goto out;

	struct udphdr *udp = (void *)iph + sizeof(*iph);
	if ((void *)udp + sizeof(*udp) > data_end)
		goto out;

	if (udp->dest != bpf_htons(PORT))
		goto out;

	// RR
	cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
	if (cpu_max)
	{
		cpu_iterator = bpf_map_lookup_elem(&cpus_iterator, &key0);
		if (!cpu_iterator)
			return XDP_ABORTED;
		cpu_idx = *cpu_iterator;

		*cpu_iterator += 1;
		if (*cpu_iterator == *cpu_max)
			*cpu_iterator = 0;

		cpu_selected = bpf_map_lookup_elem(&cpus_available, &cpu_idx);
		if (!cpu_selected)
			return XDP_ABORTED;
		cpu_dest = *cpu_selected;

		// /* Check cpu_dest is valid */
		// cpu_lookup = bpf_map_lookup_elem(&cpu_map, &cpu_dest);
		// if (!cpu_lookup)
		// 	return XDP_DROP;

		// if (cpu_dest >= MAX_CPUS)
		// 	return XDP_ABORTED;

		return bpf_redirect_map(&cpu_map, cpu_dest, 0);
	}

out:
	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
