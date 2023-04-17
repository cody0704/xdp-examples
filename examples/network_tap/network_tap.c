// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_INTERFACE 1

static unsigned const short PORT = 7999;

struct bpf_elf_map SEC("maps") tx_if = {
		.type = BPF_MAP_TYPE_DEVMAP,
		.size_key = sizeof(__u32),
		.size_value = sizeof(__u32),
		.max_elem = MAX_INTERFACE,
		.pinning = PIN_GLOBAL_NS,
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int action = XDP_PASS;

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

	if (udp->dest != bpf_htons(PORT) && udp->source != bpf_htons(PORT))
		goto out;

	action = bpf_redirect_map(&tx_if, ctx->ingress_ifindex, 0);

out:
	return action;
}

// Basic license just for compiling the object code
char _license[] SEC("license") = "GPL";