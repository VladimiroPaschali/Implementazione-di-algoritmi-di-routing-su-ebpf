/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stddef.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>


#include "common_kern_user.h" /* defines: struct datarec; */


struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif
//cerca il tipo di protocollo ethernet all'interno del pacchetto, IP
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;
	nh->pos += hdrsize;
	*ethhdr = eth;


	return eth->h_proto; /* network-byte-order */
}
//cerca il tipo di protocollo tcp udp nel pacchetto ip
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	if(hdrsize < sizeof(*iph))
		return -1;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
	//return iph->saddr;//ip address source
}
//cerca la porta di destinazione all'interno dell'header tcp
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;
	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	/* Sanity check packet field is valid */
	if(len < sizeof(*h))
		return -1;

	/* Variable-length TCP header, need to use byte-based arithmetic */
	if (nh->pos + len > data_end)
		return -1;

	nh->pos += len;
	*tcphdr = h;

	return h->dest;
}


SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	int nh_type;
	nh.pos = data;
	struct datarec *rec;
	__u32 action = XDP_PASS;//azione di default
	struct ethhdr *eth;
	__u64 bytes = data_end - data;

	nh_type = parse_ethhdr(&nh, data_end, &eth);
	if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		//cerca tipo di protocollo tcp in iphdr
		nh_type = parse_iphdr(&nh, data_end, &iph);
		if (nh_type == IPPROTO_TCP){
			struct tcphdr *tcp;
			//cerca numero porta in tcphdr e blocca l'80
			nh_type = parse_tcphdr(&nh, data_end, &tcp);
			if (nh_type == bpf_ntohs(80))
				action = XDP_DROP;
		}

	}

	//carica nella mappa xdp_stats_map i pacchetti e il numero di bytes
	rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
			return XDP_ABORTED;

	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}
