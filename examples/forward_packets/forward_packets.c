// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

// #include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SERVERS 1

static unsigned const short PORT = 7999;

#pragma pack(push, 1)
struct dest_info
{
	__u32 saddr;
	__u32 daddr;
	__u8 smac[6];
	__u8 dmac[6];
	__u32 ifindex;
};
#pragma pack(pop)

struct bpf_elf_map SEC("maps") servers = {
		.type = BPF_MAP_TYPE_HASH,
		.size_key = sizeof(__u32),
		.size_value = sizeof(struct dest_info),
		.max_elem = MAX_SERVERS,
		.pinning = PIN_GLOBAL_NS,
};

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#define MAX_UDP_LENGTH 1480

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++)
	{
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
	iph->check = 0;
	unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
	return csum_fold_helper(csum);
}

static __always_inline __u16 udp_checksum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
	udph->check = 0;

	// So we can overflow a bit make this __u32
	__u32 csum_buffer = 0;
	__u16 *buf = (void *)udph;

	csum_buffer += (__u16)iph->saddr;
	csum_buffer += (__u16)(iph->saddr >> 16);
	csum_buffer += (__u16)iph->daddr;
	csum_buffer += (__u16)(iph->daddr >> 16);
	csum_buffer += (__u16)iph->protocol << 8;
	csum_buffer += udph->len;

	// Compute checksum on udp header + payload
	for (int i = 0; i < MAX_UDP_LENGTH; i += 2)
	{
		if ((void *)(buf + 1) > data_end)
		{
			break;
		}

		csum_buffer += *buf;
		buf++;
	}

	if ((void *)buf + 1 <= data_end)
	{
		// In case payload is not 2 bytes aligned
		csum_buffer += *(__u8 *)buf;
	}

	// Add any cksum overflow back into __u16
	__u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
	csum = ~csum;

	return csum;
}

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	int action = XDP_PASS;
	__u32 key = 0;

	// dest_info
	struct dest_info *tnl;

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

	// Get Forward Obj
	tnl = bpf_map_lookup_elem(&servers, &key);
	if (!tnl)
	{
		return XDP_DROP;
	}

	// Call Info
	iph->saddr = tnl->saddr;
	memcpy(eth->h_source, tnl->smac, ETH_ALEN);

	iph->daddr = tnl->daddr;
	memcpy(eth->h_dest, tnl->dmac, ETH_ALEN);

	// iph->id = iph->id + 1;
	iph->check = iph_csum(iph);
	udp->check = udp_checksum(iph, udp, data_end);

	action = bpf_redirect(tnl->ifindex, 0);

out:
	return action;
}

// Basic license just for compiling the object code
char _license[] SEC("license") = "GPL";