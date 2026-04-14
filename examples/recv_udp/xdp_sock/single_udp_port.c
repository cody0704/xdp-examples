// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// PORT is set from userspace via the Variables API before loading.
volatile const __u16 PORT = 0;

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if ((void *)eth + sizeof(*eth) > data_end)
		return XDP_PASS;

	if (bpf_htons(eth->h_proto) != ETH_P_IP)
		return XDP_PASS;

	struct iphdr *ip = data + sizeof(*eth);
	if ((void *)ip + sizeof(*ip) > data_end)
		return XDP_PASS;

	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udp = (void *)ip + sizeof(*ip);
	if ((void *)udp + sizeof(*udp) > data_end)
		return XDP_PASS;

	// Only pass matching UDP packets to the kernel network stack.
	if (udp->dest == bpf_htons(PORT))
		return XDP_PASS;

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";