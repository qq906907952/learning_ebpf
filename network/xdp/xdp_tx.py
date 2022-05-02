from bcc import BPF

in_dev = "wlan0"

text='''
/*
这个程序主要是把udp 收到的包原路返回 对应 xdp action XDP_TX
*/
#include<uapi/linux/tcp.h>
#include<uapi/linux/ip.h>
#include<uapi/linux/in.h>
#include<uapi/linux/if_ether.h>
#include<uapi/linux/udp.h>

static void exchange_mac( struct ethhdr *eth){
    unsigned char s[6];
    unsigned char d[6];
    __builtin_memcpy(s,eth->h_source,6);
    __builtin_memcpy(d,eth->h_dest,6);
    __builtin_memcpy(eth->h_source,d,6);
    __builtin_memcpy(eth->h_dest,s,6);
}

static void exchange_ip(struct iphdr *ip){
    __be32 saddr = ip->saddr;
    __be32 daddr = ip->daddr;
    ip->saddr=daddr;
    ip->daddr=saddr;
}

static void exchange_port(struct udphdr *udp){
    __be16 sport = udp->source;
    __be16 dport = udp->dest;
    udp->source=dport;
    udp->dest=sport;
    udp->check=0;
    
}

int return_packet(struct xdp_md *ctx){
    void * data = (void*)(unsigned long)ctx->data;
    void * data_end = (void*)(unsigned long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    
    unsigned short dport = 12345;
    
    eth=data;
    long off = sizeof(*eth);

    if (data+off>data_end){
        return XDP_DROP;
    }

    if (!(bpf_ntohs(eth->h_proto)==ETH_P_IP)){ //not ip protocol
        return XDP_PASS;
    }
    ip =  data+off;
    off+=sizeof(*ip);
    if(data+off>data_end){
        return XDP_DROP;
    }

    if (!(ip->version!=4 || ip->protocol==IPPROTO_UDP)){
        return XDP_PASS;
    }
        
    udp=data+off;
    off+=sizeof(*udp);
    if (data+off>data_end){
        return XDP_DROP;
    }
        
    if (bpf_ntohs(udp->dest)==dport){
        //交换 mac ip 和udp端口
        exchange_mac(eth);
        exchange_ip(ip);
        exchange_port(udp);
        bpf_trace_printk("======================");
        bpf_trace_printk("sip: %d | dip: %d",bpf_ntohl(ip->saddr),bpf_ntohl(ip->daddr));
        bpf_trace_printk("sport: %d | dport: %d",bpf_ntohs(udp->source),bpf_ntohs(udp->dest));
        //当前网卡原路返回
        return XDP_TX;
    }
     return XDP_PASS;
}

'''


b=BPF(text=text)
b.attach_xdp(in_dev, b.load_func("return_packet", b.XDP))
try:
    b.trace_print()
except Exception as e:
    print(e)
    pass
finally:
    b.remove_xdp(in_dev)