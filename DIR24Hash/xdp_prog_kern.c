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
//un array per le /24 8 hashmap per gli ip da /25 a /32
struct bpf_map_def SEC("maps") lpm24 = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 16777216,
};
struct bpf_map_def SEC("maps") lpm32 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 1600,
};
struct bpf_map_def SEC("maps") lpm31 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 16,
};
struct bpf_map_def SEC("maps") lpm30 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 90,
};
struct bpf_map_def SEC("maps") lpm29 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 195,
};
struct bpf_map_def SEC("maps") lpm28 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 219,
};
struct bpf_map_def SEC("maps") lpm27 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 168,
};
struct bpf_map_def SEC("maps") lpm26 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 139,
};
struct bpf_map_def SEC("maps") lpm25 = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u8),
	.max_entries = 120,
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
		//maschera gli ip con la maschera 255.0.0.0
		__u32 ipmask24= ip_src&16777215;
		__u32 mask[33]={4294967295,4278190079,4244635647,4177526783,4043309055,3774873599,3238002687,2164260863,
    				2164260863,16580607,16318463,15794175,14745599,12648447,8454143,65535,65279,64767,63743,61695,57599,49407,33023,255,254,252,248,240,224,192,128};
		__u32 ipmask[33];

		//mette in and l'ip con le 32 maschere per mascherarli
		for(int i=0; i<32;i++){
			ipmask[i]=ip_src&mask[i];
		}

		value = bpf_map_lookup_elem(&lpm24, &ipmask24);
		//l'ip sta solo nella prima mappa
		if(value == 0){
			rec = bpf_map_lookup_elem(&dati, &i[24]);
			if (!rec)
			    return XDP_ABORTED;
			rec->rx_packets++;
			rec->rx_bytes += bytes;
		}
		//value = 1 ip nelle mappe da 32 a 25
		else{
			if(bpf_map_lookup_elem(&lpm32, &ipmask[0])){
            rec = bpf_map_lookup_elem(&dati, &i[32]);
            if (!rec)
                return XDP_ABORTED;
            rec->rx_packets++;
            rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm31, &ipmask[1])){
							rec = bpf_map_lookup_elem(&dati, &i[31]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm30, &ipmask[2])){
							rec = bpf_map_lookup_elem(&dati, &i[30]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm29, &ipmask[3])){
							rec = bpf_map_lookup_elem(&dati, &i[29]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm28, &ipmask[4])){
							rec = bpf_map_lookup_elem(&dati, &i[28]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm27, &ipmask[5])){
							rec = bpf_map_lookup_elem(&dati, &i[27]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm26, &ipmask[6])){
							rec = bpf_map_lookup_elem(&dati, &i[26]);
				if (!rec)
					return XDP_ABORTED;
				rec->rx_packets++;
				rec->rx_bytes += bytes;
			}else if(bpf_map_lookup_elem(&lpm25, &ipmask[7])){
							rec = bpf_map_lookup_elem(&dati, &i[25]);
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