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
#include <stdbool.h>
#include "common_kern_user.h"
 //crea mappe necessarie
union key_4 {
	__u32 b32[2];
	__u8 b8[8];
};

struct bpf_map_def SEC("maps") lpm = {
	.type        = BPF_MAP_TYPE_LPM_TRIE,
	.key_size    = sizeof(__u64),
	.value_size  = sizeof(__u8),
	.max_entries = 1000000,
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") dati = {
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = 33,
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
	if (nh->pos + hdrsize > data_end)
		return -1;
	nh->pos += hdrsize;
	*ethhdr = eth;
	return eth->h_proto;
}
//cerca l'indirizzo ip sorgente nel pacchetto ip lo ritorna in binario
static __always_inline __u32 parse_iphdr(struct hdr_cursor *nh,
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
	//return iph->protocol;
	return iph->saddr;//ip address source
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
	//azione di default = drop
	__u32 action = XDP_DROP;
	//indici dati
    __u32 i[33]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
    __u8 *value;


	struct ethhdr *eth;
	//calcola byte per pacchetto
	__u64 bytes = data_end - data;
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	//controlla che il pacchetto sia di tipo ip
	if (nh_type == bpf_htons(ETH_P_IP)) {
		struct iphdr *iph;
		//salva ip sorgente
		__u32 ip_src = (long)parse_iphdr(&nh, data_end, &iph);

		//salva l'ip in formato key4 come è salvato nel trie
		union key_4 key4;
  		key4.b32[0] = 32;
		key4.b8[4] = ip_src & 0xff;
		key4.b8[5] = (ip_src >> 8) & 0xff;
		key4.b8[6] = (ip_src >> 16) & 0xff;
		key4.b8[7] = (ip_src >> 24) & 0xff;

		//controlla se è presente nel trie
		value = bpf_map_lookup_elem(&lpm,&key4);

		if (value){
	  		if(*value>=0&&*value<=32){
				//aumenta il contatore dei pacchetti e dei bytes per la mappa dati in output letta dal file kernel
	  			rec = bpf_map_lookup_elem(&dati, &i[*value]);
				if (!rec)
				    return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}
  		}
		//salva nella mappa all'indirizzo 0 che contiene i valori totali
        rec = bpf_map_lookup_elem(&dati, &i[0]);
        if (!rec)
            return XDP_ABORTED;
        rec->rx_packets++;
        rec->rx_bytes += bytes;
	}
	return action;
}