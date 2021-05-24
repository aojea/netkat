#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

/*
 * Constants that define the filter:
 * ipFamily: ipv4 or ipv6
 * protocol: TCP or UDP
 * TODO: destIP
 * destPort
 * srcPort
 */


static volatile unsigned const char PROTO;
static volatile unsigned const char PROTO = IPPROTO_ICMP;

static volatile unsigned const char IP_FAMILY;
static volatile unsigned const char IP_FAMILY = 4;

static volatile unsigned const short SRC_PORT;
static volatile unsigned const short SRC_PORT = 0;
static volatile unsigned const short DST_PORT;
static volatile unsigned const short DST_PORT = 0;

/*
 * classifier return 1 if the packet matches the filter
 * 0 of it does not
 */

int classifier(struct __sk_buff *skb)
{
     __u16 dst_port = 0;
     __u16 src_port = 0;

     void *data = (void *)(long)skb->data;
     void *data_end = (void *)(long)skb->data_end;

     // process IPv4
     if  (skb->protocol == bpf_htons(ETH_P_IP) &&
          IP_FAMILY == 4) {
          if (data + sizeof(struct iphdr) > data_end) { 
               return 0; 
          }
          
          struct iphdr *ip = data;
          // TODO filter IP ip_src = iph->saddr;

          if (ip->protocol != PROTO) {
               return 0;
          }
          __u8 *ihlandversion = data;
          __u8 ihlen = (*ihlandversion & 0xf) * 4;
          if (data + ihlen + sizeof(struct tcphdr) > data_end) { 
               return 0; 
          }
          struct tcphdr *tcp = data + ihlen;
          src_port = __bpf_ntohs(tcp->source);
          dst_port = __bpf_ntohs(tcp->dest);
     // process IPv6
     } else if (skb->protocol == bpf_htons(ETH_P_IPV6) &&
          IP_FAMILY == 6) {
          struct ipv6hdr *ipv6 = data;
          __u8 ihlen = sizeof(struct ipv6hdr);
          if (((void *) ipv6) + ihlen > data_end) { 
               return 0; 
          }

          if (ipv6->nexthdr != PROTO) {
               return 0;
          }

          if (((void *) ipv6) + ihlen + sizeof(struct tcphdr) > data_end) { 
               return 0; 
          }
          struct tcphdr *tcp = ((void *) ipv6) + ihlen;
          src_port = __bpf_ntohs(tcp->source);
          dst_port = __bpf_ntohs(tcp->dest);
     }

     if (src_port == DST_PORT &&
          dst_port == SRC_PORT) {
               return 1;
     }
     return 0; /* no match */
}

/*
 * Capture the packets that match the filter
 */

SEC("socket")
int socket_filter(struct __sk_buff *skb)
{
     void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	if (data + sizeof(struct ethhdr) > data_end) {
		return 0;
     }

     // allow arp
     if (skb->protocol == bpf_htons(ETH_P_ARP)) {
          return 1;
     }
     // TODO allow icmp ND

     // allow packets mathing the filter
     return classifier(skb);
}

/*
 * Drop the packets that doesn't match the filter
 */

SEC("socket")
int tc_ingress(struct __sk_buff *skb)
{
     void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;

	if (data + sizeof(struct ethhdr) > data_end) {
		return TC_ACT_SHOT;
     }

     // reject packets matching the filter
     if (classifier(skb)) {
          return TC_ACT_SHOT;
     }
     return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
