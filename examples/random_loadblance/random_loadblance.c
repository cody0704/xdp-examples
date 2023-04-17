// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdint.h>

// #include <bpf/parse_helpers.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") servers = {
		.type = BPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(__u32),
		.value_size = sizeof(__u32),
		.max_entries = 1,
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	__u32 key0 = 0;

	// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) > data_end)
		goto out;

	__u16 h_proto = eth->h_proto;
	if (bpf_htons(h_proto) != ETH_P_IP)
		goto out;

	struct iphdr *iph = data + sizeof(*eth);

	if ((void *)iph + sizeof(*iph) > data_end)
		goto out;

	struct udphdr *udp = (void *)iph + sizeof(*iph);
	if ((void *)udp + sizeof(*udp) > data_end)
		goto out;

	if (iph->protocol != IPPROTO_UDP)
		goto out;

	unsigned int randservers;
	__builtin_get_random_bytes(&randservers, sizeof(randservers));
	int server = randservers % 20;
	if (udp->dest == bpf_htons(5999))
	{
		udp->dest = bpf_htons(server + 6000);
	}

out:
	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
