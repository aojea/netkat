/* Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define _htonl __builtin_bswap32

#define PIN_GLOBAL_NS		2
struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};


SEC("classifier")
int _ingress(struct __sk_buff *skb)
{
	struct bpf_tunnel_key tkey = {};
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;
	int key = 0, *ifindex;

	int ret;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		char fmt4[] = "ingress forward to saddr:%d daddr4:%x\n";
		struct iphdr *iph = data + sizeof(*eth);

		if (data + sizeof(*eth) + sizeof(*iph) > data_end)
			return TC_ACT_OK;

		bpf_trace_printk(fmt4, sizeof(fmt4), _htonl(iph->saddr),
				 _htonl(iph->daddr));

		if (iph->protocol != IPPROTO_TCP)
			return TC_ACT_OK;


		return TC_ACT_OK;
	} else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		char fmt6[] = "ingress forward to saddr:%d daddr6:%x::%x\n";
		struct ipv6hdr *ip6h = data + sizeof(*eth);

		if (data + sizeof(*eth) + sizeof(*ip6h) > data_end)
			return TC_ACT_OK;

		if (ip6h->nexthdr != IPPROTO_IPIP &&
		    ip6h->nexthdr != IPPROTO_IPV6)
			return TC_ACT_OK;

		bpf_trace_printk(fmt6, sizeof(fmt6), ip6h->daddr.s6_addr32[0],
				 _htonl(ip6h->daddr.s6_addr32[0]),
				 _htonl(ip6h->daddr.s6_addr32[3]));
		return TC_ACT_OK;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
