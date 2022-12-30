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

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	// interface id number
	unsigned ifindex = 0;

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

	bpf_redirect(ifindex, 0);

out:
	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
