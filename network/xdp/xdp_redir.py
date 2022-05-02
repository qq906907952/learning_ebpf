from bcc import BPF
import ctypes as ct

in_dev = "eth0"
out_dev_idx = 10  # ip link 对应的idx

text='''
#include<uapi/linux/tcp.h>
#include<uapi/linux/ip.h>
#include<uapi/linux/in.h>
#include<uapi/linux/if_ether.h>
#include<uapi/linux/udp.h>

BPF_DEVMAP(dev,10);

static void __add_csum_16(unsigned short *csum,unsigned short add){
    int res = *csum + add;
    *csum = (res & 0xffff) + (res >> 16) ;
}

//增量计算检验和 参考 rfc1624
static __sum16 new_sum_16(void *__from, void *__to, u32 size,__sum16 __old_sum ){
   unsigned char* from = (unsigned char *)__from; 
   unsigned char* to = (unsigned char *)__to; 
   unsigned short  __new_sum = ~__old_sum;
   for(int i =0;i<size;i+=2){
        unsigned short _from = (from[i]<<8) + from[i+1];
        unsigned short _to = (to[i]<<8) + to[i+1];
        __add_csum_16(&__new_sum,~_from);
        __add_csum_16(&__new_sum,_to);
   }
   return ~__new_sum;
}


static void ip_set_daddr(struct iphdr * ip, unsigned char * daddr){
    __be32 old_daddr = ip->daddr;
    __builtin_memcpy(&ip->daddr,daddr,4);
    ip->check = bpf_htons(new_sum_16(&old_daddr,daddr,4,bpf_ntohs(ip->check)));

} 

static void eth_set_dmac(struct ethhdr *eth,unsigned char * dmac ){
    __builtin_memcpy(eth->h_dest,dmac,6);
}

int redirect(struct xdp_md *ctx){
    //一下是需要修改的4个变量
    unsigned char to_daddr[4] = {172,17,0,2};
    unsigned short from_dport = 9999;
    unsigned short to_dport = 1234;
    unsigned char to_mac[6] = {0x4a,0x25,0x8e,0xec,0x20,0x7c};
    
    void * data = (void*)(unsigned long)ctx->data;
    void * data_end = (void*)(unsigned long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    


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
        
        
    if (bpf_ntohs(udp->dest)==from_dport){
        eth_set_dmac(eth,to_mac); //修改目的mac
        ip_set_daddr(ip,to_daddr); //修改目的ip地址
        udp->dest = bpf_htons(to_dport); //修改目的端口
        udp->check = 0; //关闭udp校验和
        
        int redir = dev.redirect_map(0,0);
        bpf_trace_printk("redir return %d",redir);
        return redir;      
         
    }
    return XDP_PASS;
}

'''

b = BPF(text=text)
dev = b.get_table("dev")
dev[0] = ct.c_int(out_dev_idx)
b.attach_xdp(in_dev, b.load_func("redirect", b.XDP))
try:
    b.trace_print()
except Exception as e:
    print(e)
    pass
finally:
    b.remove_xdp(in_dev)