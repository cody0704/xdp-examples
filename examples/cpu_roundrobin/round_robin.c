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

#define MAX_CPUS 28

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

struct bpf_map_def SEC("maps") xsks_map = {
		.type = BPF_MAP_TYPE_XSKMAP,
		.key_size = sizeof(int),
		.value_size = sizeof(int),
		.max_entries = MAX_SOCKS,
};

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

struct datarec
{
	__u64 processed;
	__u64 dropped;
	__u64 issue;
};

struct bpf_map_def SEC("maps") rx_cnt = {
		.type = BPF_MAP_TYPE_PERCPU_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(struct datarec),
		.max_entries = 1,
};

SEC("xdp_cpu_map0")
int xdp_prognum0_no_touch(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 *cpu_selected;
	__u32 cpu_dest;
	__u32 key = 0;

	/* Only use first entry in cpus_available */
	cpu_selected = bpf_map_lookup_elem(&cpus_available, &key);
	if (!cpu_selected)
		return XDP_ABORTED;
	cpu_dest = *cpu_selected;

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (cpu_dest >= MAX_CPUS)
	{
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}

SEC("xdp_cpu_map2_round_robin")
int xdp_prognum2_round_robin(struct xdp_md *ctx)
{
	struct datarec *rec;
	__u32 cpu_dest;
	__u32 key0 = 0;

	__u32 *cpu_selected;
	__u32 *cpu_iterator;
	__u32 *cpu_max;
	__u32 cpu_idx;

	cpu_max = bpf_map_lookup_elem(&cpus_count, &key0);
	if (!cpu_max)
		return XDP_ABORTED;

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

	/* Count RX packet in map */
	rec = bpf_map_lookup_elem(&rx_cnt, &key0);
	if (!rec)
		return XDP_ABORTED;
	rec->processed++;

	if (cpu_dest >= MAX_CPUS)
	{
		rec->issue++;
		return XDP_ABORTED;
	}

	return bpf_redirect_map(&cpu_map, cpu_dest, 0);
}
// Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
