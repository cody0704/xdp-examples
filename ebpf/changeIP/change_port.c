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

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
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

	if (udp->dest == bpf_htons(5999))
	{
		// modified packet/path
		swap_src_dst_ipv4(iph);
		udp->dest = bpf_htons(6001);

		/* Set a proper destination address */
		// memcpy(eth->h_dest, dst, ETH_ALEN);
	}

out:
	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "LGPL-2.1 or BSD-2-Clause";
