#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define DEBUG 1
#ifdef DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)                            \
	(                                                  \
		{                                              \
			char ____fmt[] = fmt;                      \
			bpf_trace_printk(____fmt, sizeof(____fmt), \
							 ##__VA_ARGS__);           \
		})
#else
#define bpf_debug(fmt, ...) \
	{                       \
	}                       \
	while (0)
#endif

SEC("classifier")
int _ingress(struct __sk_buff *skb)
{
	__be32 dest_ip = 0, src_ip = 0;
	__be16 dest_port = 0, src_port = 0;
	__u16 h_proto;
	__u64 nh_off;
	int ipproto;

	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end)
		return TC_ACT_OK;

	/* allow arp */
	h_proto = eth->h_proto;
	if (h_proto == __constant_htons(ETH_P_RARP) ||
		h_proto == __constant_htons(ETH_P_ARP))
	{
		return TC_ACT_OK;
	}

	/* allow non IPv4 */
	if (h_proto != __constant_htons(ETH_P_IP))
		return TC_ACT_OK;

	/* get IP header */
	struct iphdr *iph = data + nh_off;
	if (iph + 1 > data_end)
		return TC_ACT_OK;

	/* get IP transport protocol */
	src_ip = iph->saddr;
	dest_ip = iph->daddr;
	ipproto = iph->protocol;
	bpf_debug("ip src %x ip dst %x", src_ip, dest_ip);

	/* get transport ports */
	struct udphdr *udph;
	struct tcphdr *tcph;

	switch (ipproto)
	{
	case IPPROTO_UDP:
		udph = iph + 1;
		if (udph + 1 > data_end)
		{
			bpf_debug("Invalid UDPv4 packet: L4off:%llu\n",
					  sizeof(struct iphdr) + sizeof(struct udphdr));
			return TC_ACT_OK;
		}
		src_port = __bpf_ntohs(udph->source);
		dest_port = __bpf_ntohs(udph->dest);
		break;
	case IPPROTO_TCP:
		tcph = iph + 1;
		if (tcph + 1 > data_end)
		{
			bpf_debug("Invalid TCPv4 packet: L4off:%llu\n",
					  sizeof(struct iphdr) + sizeof(struct tcphdr));
			return TC_ACT_OK;
		}
		src_port = __bpf_ntohs(tcph->source);
		dest_port = __bpf_ntohs(tcph->dest);
		break;
	}
	bpf_debug("src port %x dst port %x", src_port, dest_port);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";