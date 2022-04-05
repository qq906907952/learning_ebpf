from bcc import BPF
import ctypes as ct

in_dev = "eth0"
out_dev_idx = 1  # ip link 对应的idx. 1 一般是lo

text = '''
/*
效果类似 iptables -t nat -A PREROUTING -p udp --sport 53 -j DNAT --to-destination 127.0.0.1:1234
*/  

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

static void cal_ip_csum(struct iphdr * ip){
    ip->check = 0;
    unsigned char * ip_ptr = (char *)ip;
    int csum = 0;
    for (int i=0;i<sizeof(*ip);i+=2){
        unsigned short t = (ip_ptr[i]<<8) + ip_ptr[i+1];
        csum+=t;
    }
    ip->check = bpf_htons(~(unsigned short)((csum & 0xffff) + (csum >>16)));
}

int divert(struct xdp_md *ctx){
    void * data = (void*)(unsigned long)ctx->data;
    void * data_end = (void*)(unsigned long)ctx->data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct udphdr *udp;
    
    unsigned short sport = 53;
    unsigned short to_sport = 12345;
    unsigned short to_dport = 1234;
    unsigned char to_daddr[4] = {127,0,0,1};


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
        
        
    if (bpf_ntohs(udp->source)==sport){
        //修改ip包数据 
        __be32 __to_addr = *(__be32 *)to_daddr;
        //新校验和
        __sum16 new_csum = new_sum_16(&ip->daddr,to_daddr,4,bpf_ntohs(ip->check));
        ip->daddr = __to_addr;
        ip->check = bpf_htons(new_csum);
        //cal_ip_csum(ip);
        
        //修改udp包数据
        udp->source=htons(to_sport);
        udp->dest=htons(to_dport);
        //关闭udp校验和校验
        udp->check=0;
        bpf_trace_printk("sport %d to ip:%d port %d",sport,*(unsigned int*)to_daddr,to_dport);
      
        //redirect 本地测试的结果是只能重定向到lo 重定向到其他网卡 抓包时抓不到 即使redir到lo 监听127.0.0.1和对应端口也不能接受到数据 目前还不知道原因. 
        //int redir = dev.redirect_map(0,0);
        //bpf_trace_printk("redir return %d",redir);
        //return redir;      
    }

    return XDP_PASS;
}

'''

b = BPF(text=text)
dev = b.get_table("dev")
dev[0] = ct.c_int(out_dev_idx)
b.attach_xdp(in_dev, b.load_func("divert", b.XDP))
try:
    b.trace_print()
except Exception:
    b.remove_xdp(in_dev)
