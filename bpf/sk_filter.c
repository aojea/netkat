
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

#define AF_INET 2	/* IP protocol family.  */
#define AF_INET6 10 /* IP version 6.  */

/*
 * #define PROTO IPPROTO_ICMP 
 * #define IP_FAMILY AF_INET		 
 * #define SRC_IP 0xAC110002 
 * #define DST_IP 0			   
 * #define SRC_PORT 0		    
 * #define DST_PORT 80		   
*/

/*
 * Constants that define the filter:
 * ipFamily: ipv4 or ipv6
 * protocol: TCP or UDP
 * destIP
 * srcIP
 * destPort
 * srcPort
 */

static volatile unsigned const char IP_FAMILY;
static volatile unsigned const char IP_FAMILY = 4;

static volatile unsigned const short SRC_IP;
static volatile unsigned const short SRC_IP = 0;
static volatile unsigned const short DST_IP;
static volatile unsigned const short DST_IP = 0;

static volatile unsigned const char PROTO;
static volatile unsigned const char PROTO = IPPROTO_ICMP;

static volatile unsigned const short SRC_PORT;
static volatile unsigned const short SRC_PORT = 0;
static volatile unsigned const short DST_PORT;
static volatile unsigned const short DST_PORT = 0;

SEC("socket")
int _socket(struct __sk_buff *skb)
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
		return 1;

	/* allow arp */
	h_proto = eth->h_proto;
	if (h_proto == __constant_htons(ETH_P_RARP) ||
		h_proto == __constant_htons(ETH_P_ARP))
	{
		return 1;
	}

	/* discard different protocol */
	if (h_proto != __constant_htons(ETH_P_IP) ||
		IP_FAMILY != AF_INET)
		return 0;

	/* get IP header */
	struct iphdr *iph = data + nh_off;
	if (iph + 1 > data_end)
		return 1;

	/* get IP transport protocol */
	src_ip = __bpf_ntohl(iph->saddr);
	dest_ip = __bpf_ntohl(iph->daddr);
	ipproto = iph->protocol;
	bpf_debug("ip src %x ip dst %x", src_ip, dest_ip);

	// if SRC_PORT specified check it
	if (SRC_IP != 0 &&
		src_ip != SRC_IP)
	{
		bpf_debug("ip src %x does not match %x", src_ip, SRC_IP);
		return 0;
	}

	// if DST_PORT specified check it
	if (DST_IP != 0 &&
		dest_ip != DST_IP)
	{
		bpf_debug("ip dest %x does not match %x", dest_ip, DST_IP);
		return 0;
	}

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
			return 1;
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
			return 1;
		}
		src_port = __bpf_ntohs(tcph->source);
		dest_port = __bpf_ntohs(tcph->dest);
		break;
	default:
		return 0;
	}
	bpf_debug("src port %x dst port %x", src_port, dest_port);

	// if SRC_PORT specified check it
	if (SRC_PORT != 0 &&
		src_port != SRC_PORT)
	{
		return 0;
	}

	// if DST_PORT specified drop it
	// if it matches 5-tuple
	if (DST_PORT != 0 &&
		dest_port != SRC_PORT)
	{
		return 1;
	}

	return 0;
}

char _license[] SEC("license") = "GPL";