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


SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;

	nh.pos = data;
	struct datarec *rec;
	//azione di default = drop
	__u32 action = XDP_DROP;
	//calcola byte per pacchetto
	__u64 bytes = data_end - data;

	//carica nella mappa xdp_stats_map il pacchetto bloccato e il numero di bytes
	rec = bpf_map_lookup_elem(&xdp_stats_map, &action);
	if (!rec)
			return XDP_ABORTED;

	rec->rx_packets++;
	rec->rx_bytes += bytes;

	return action;
}