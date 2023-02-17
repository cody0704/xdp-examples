// +build ignore

#include <linux/bpf.h>
// #include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SERVERS 1

struct dest_info
{
	__u32 saddr;
	__u32 daddr;
	__u8 smac[6];
	__u8 dmac[6];
	__u32 ifindex;
};

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

static __always_inline __u16 ip_checksum(unsigned short *buf, int bufsz)
{
	unsigned long sum = 0;

	while (bufsz > 1)
	{
		sum += *buf;
		buf++;
		bufsz -= 2;
	}

	if (bufsz == 1)
	{
		sum += *(unsigned char *)buf;
	}

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

#define MAX_UDP_LENGTH 1480

static __always_inline __u16 caludpcsum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
	__u32 csum_buffer = 0;
	__u16 *buf = (void *)udph;

	// Compute pseudo-header checksum
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
	// interface id number
	// __u16 ifindex = 5;

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

	if (udp->dest != bpf_htons(7999))
	{
		return XDP_PASS;
	}

	// Get Forward Obj
	tnl = bpf_map_lookup_elem(&servers, &key);
	if (!tnl)
	{
		return XDP_DROP;
	}

	/* allocate a destination using packet hash and map lookup */
	// 192.168.0.122 = 3232235642
	// iph->saddr = htonl(3232235642)
	// 192.168.0.137 = 3232235657
	// iph->daddr = htonl(3232235657);

	// OK
	// 192.168.249.50 = 3232299314
	// iph->daddr = htonl(3232299314);
	// 192.168.249.107 = 3232299371
	// iph->saddr = htonl(3232299371);

	// unsigned char src[ETH_ALEN] = {0x82, 0x81, 0x76, 0x6a, 0x09, 0x90};
	// unsigned char dst[ETH_ALEN] = {0x8e, 0xd2, 0xcd, 0x8c, 0x57, 0x12};
	// memcpy(eth->h_source, src, ETH_ALEN);
	// memcpy(eth->h_dest, dst, ETH_ALEN);
	// END

	// Call Info
	iph->saddr = tnl->saddr;
	iph->daddr = tnl->daddr;
	memcpy(eth->h_source, tnl->smac, ETH_ALEN);
	memcpy(eth->h_dest, tnl->dmac, ETH_ALEN);

	bpf_printk("1.redirect sip %d", iph->saddr);
	bpf_printk("2.redirect dip %d", iph->daddr);
	bpf_printk("3.redirect mac %d %d %d", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2]);
	bpf_printk("4.redirect mac %d %d %d", eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	// iph->id = iph->id + 1;

	iph->check = 0;
	iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));

	udp->check = 0;
	udp->check = caludpcsum(iph, udp, data_end);

	// action = bpf_redirect(ifindex, 0);
	action = bpf_redirect(tnl->ifindex, 0);

out:
	return action;
}

// Basic license just for compiling the object code
char _license[] SEC("license") = "GPL";