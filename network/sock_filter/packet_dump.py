import socket

from bcc import BPF
from bcc import BPFProgType
import struct

dev = "lo"

DUMP_STS_IGNORE = b'\x00'
DUMP_STS_P = b'\x01'


def inet_ntoa_be(i):
    return ".".join([str(i) for i in struct.pack(">I",i)])
def eth_ntoa_be(m):
    return ':'.join(["{:02X}".format(int(i)) for i in bytearray(m)])

def convert_proto(i):
    if i==socket.IPPROTO_TCP:
        return "tcp"
    elif i==socket.IPPROTO_UDP:
        return "udp"
    elif i==socket.IPPROTO_ICMP:
        return "icmp"
    else :
        return str(i)

text = '''
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

struct packet {
    unsigned char smac[6];
    unsigned char dmac[6];
    unsigned int  saddr;
    unsigned  int  daddr;
    char proto;
    short len;
    unsigned  short sport;
    unsigned  short dport;
    char p_sts;
};

#define DUMP_STS_IGNORE 0 
#define DUMP_STS_P      1

BPF_QUEUE(packet,struct packet,102400);


static inline struct packect conv_to_p(struct ethhdr *eth,struct iphdr *ip,struct udphdr *udp,struct tcphdr *tcp){
    struct packet p;
    __builtin_memset(&p,0,sizeof(p));
    
    __builtin_memcpy(p.smac,eth->h_source,6);
    __builtin_memcpy(p.dmac,eth->h_dest,6);
    p.saddr = bpf_ntohl(ip->saddr) ;
    p.daddr =  bpf_ntohl(ip->daddr) ;
    p.proto = ip->protocol;
    p.len =  bpf_ntohs(ip->tot_len);
    if(ip->protocol==IPPROTO_UDP && udp!=NULL){
        p.sport = bpf_ntohs(udp->source);
        p.dport = bpf_ntohs(udp->dest);
    }
    if(ip->protocol==IPPROTO_TCP && tcp!=NULL){
        p.sport = bpf_ntohs(tcp->source);
        p.dport = bpf_ntohs(tcp->dest);
    }
    return p;
}

int dump_ipv4_packet(struct __sk_buff *skb){
    struct ethhdr eth ;
    struct iphdr ip ;
    struct udphdr udp ;
    struct tcphdr tcp ;
    int off = 0;
    
    if ( bpf_skb_load_bytes(skb,off,&eth,sizeof(eth) )!=0){
        goto DROP;
    }
    off+=sizeof(eth);
    if (ntohs(eth.h_proto)!=ETH_P_IP){ // not ip protocol
        goto ACCEPT;
    }
    
    if ( bpf_skb_load_bytes(skb,off,&ip,sizeof(ip) )!=0){
        goto DROP;
    }
    off+=sizeof(ip);
    
    if (ip.version!=4 || ip.ihl!=5){ // ignore ip version not 4 and have other ip option 
        struct packet p = conv_to_p(&eth,&ip,NULL,NULL);
        p.p_sts = DUMP_STS_IGNORE;
        packet.push(&p,0);
        goto ACCEPT;
    }
    
    struct packet p;
    switch (ip.protocol){
    case IPPROTO_TCP:
        if ( bpf_skb_load_bytes(skb,off,&tcp,sizeof(tcp) )!=0){
            goto DROP;
        }
        p = conv_to_p(&eth,&ip,NULL,&tcp);
        break;
    case IPPROTO_UDP:
        if ( bpf_skb_load_bytes(skb,off,&udp,sizeof(udp) )!=0){
            goto DROP;
        }
        p = conv_to_p(&eth,&ip,&udp,NULL);
        break;
    case IPPROTO_ICMP:
        p = conv_to_p(&eth,&ip,NULL,NULL);
        break;
    default:
        goto ACCEPT;
    }
    p.p_sts = DUMP_STS_P;
    packet.push(&p,0);
    
    ACCEPT:
        return -1;
    DROP:
        return 0;
}


'''

b = BPF(text=text)
f = b.load_func("dump_ipv4_packet", BPFProgType.SOCKET_FILTER)
b.attach_raw_socket(f, dev)
packets = b.get_table("packet")

while 1:
    for p in packets.itervalues():
        if p.p_sts==DUMP_STS_IGNORE:
            print("smac: {}, dmac: {}, saddr: {}, daddr: {}, proto:{}, len: {} ignore".format(
                eth_ntoa_be(p.smac),eth_ntoa_be(p.dmac),inet_ntoa_be(p.saddr),inet_ntoa_be(p.daddr),convert_proto(int(p.proto[0])),p.len
            ))
        elif p.p_sts==DUMP_STS_P:
            print("smac: {}, dmac: {}, saddr: {}, daddr: {}, proto:{}, len: {}, sport: {}, dport: {}, accept".format(
                eth_ntoa_be(p.smac), eth_ntoa_be(p.dmac), inet_ntoa_be(p.saddr), inet_ntoa_be(p.daddr), convert_proto(int(p.proto[0])),p.len,p.sport,p.dport
            ))

