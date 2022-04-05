#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//这里是要nat的地址 将 dest_ip:dest_port nat 到 to_dest_ip:to_dest_port
//效果类似于
//iptables -t nat -A OUTPUT -p udp -d  dest_ip --dport dest_port -j DNAT --to-destination to_dest_ip:to_dest_port
unsigned char  dest_ip[4] = {114,114,114,114};
unsigned short dest_port = 1234;
unsigned char  to_dest_ip[4] = {192,168,199,68};
unsigned short to_dest_port = 12345;

SEC(".egress")
int egress_dnat(struct __sk_buff *skb){
	void *data = (void *)(unsigned long long)skb->data;
    void *data_end = (void *)(unsigned long long)skb->data_end;
    struct ethhdr *eth ;
    struct iphdr *ip ;
    struct udphdr *udp ;
    int eth_off = 0;
    int ip_off = 0;
    int udp_off = 0;

    eth = data;
    eth_off=sizeof(*eth);
    if (data+eth_off>data_end){
        return TC_ACT_SHOT;
    }

    if (!(bpf_ntohs(eth->h_proto)==ETH_P_IP)){ //not ip protocol
        return TC_ACT_OK;
    }

    ip = data+eth_off;
    ip_off+=eth_off+sizeof(*ip);
    if (data+ip_off>data_end){
        return TC_ACT_SHOT;
    }
    if (!(ip->protocol==IPPROTO_UDP)){ // not udp
        return TC_ACT_OK;
    }

    unsigned int *dest_ip_be32 = (unsigned int *)dest_ip;
    if (ip->daddr == *dest_ip_be32 ){ // match dest ip
        udp = data+ip_off;
        udp_off=ip_off+sizeof(*udp);
        if (data+udp_off>data_end){
            return TC_ACT_SHOT;
        }

        if (bpf_ntohs(udp->dest)==dest_port){ //match dest port
            // print trace use command `cat /sys/kernel/debug/tracing/trace_pipe`
            bpf_printk("send ip %d, dport %d",bpf_ntohl(ip->daddr),bpf_ntohs(udp->dest));

            unsigned int daddr_off =eth_off+offsetof(struct iphdr,daddr);
            unsigned int dest_port_off =ip_off+offsetof(struct udphdr,dest);

            //记录旧值,用于校验和计算
            unsigned int old_ip_daddr = ip->daddr;
            //change dest ip
            unsigned int *new_dest_ip_int = (unsigned int*)to_dest_ip;
            //针对目的地址修改重新计算ip校验和
            bpf_l3_csum_replace(skb,eth_off+offsetof(struct iphdr, check),old_ip_daddr,*new_dest_ip_int,4);
            bpf_skb_store_bytes(skb,daddr_off,(void*)to_dest_ip,4,0);


            //change dest port
            unsigned short new_dest_port_be = bpf_htons(to_dest_port);
            bpf_skb_store_bytes(skb,dest_port_off,(void*)(&new_dest_port_be),2,0);
            //udp 校验和设置0 ipv4 udp校验和0表示不校验
            //实际测试即使不修正校验和也可以成功发送数据,原因还不明确. 但是ip校验和是一定要计算的.
            int udp_csum = 0;
            bpf_skb_store_bytes(skb,ip_off+offsetof(struct udphdr, check),(void*)(&udp_csum),2,0);


            /*
            这里引用 `https://docs.cilium.io/en/v1.8/bpf/` 下面的一段说明:

            Some networking BPF helper functions such as bpf_skb_store_bytes might change the size of a packet data.
            As verifier is not able to track such changes, any a priori reference to the data will be invalidated by verifier.
            Therefore, the reference needs to be updated before accessing the data to avoid verifier rejecting a program.

            */

            data = (void *)(unsigned long long)skb->data;
            data_end = (void *)(unsigned long long)skb->data_end;
            ip = (struct iphdr *) ((unsigned long long)data + eth_off);
            udp = (struct udphdr *) ((unsigned long long)data + ip_off);
            if (data+udp_off>data_end){
                return TC_ACT_SHOT;
            }

            bpf_printk("send modify to_ip %d, to_dport %d",bpf_ntohl(ip->daddr),bpf_ntohs(udp->dest));
        }
    }
	return TC_ACT_OK;
}


//snat是dnat的反向操作, 用于回包时修改源地址
SEC(".ingress")
int ingress_snat(struct __sk_buff *skb){
    void *data = (void *)(unsigned long long)skb->data;
    void *data_end = (void *)(unsigned long long)skb->data_end;
    struct ethhdr *eth ;
    struct iphdr *ip ;
    struct udphdr *udp ;
    int eth_off = 0;
    int ip_off = 0;
    int udp_off = 0;

    eth = data;
    eth_off=sizeof(*eth);
    if (data+eth_off>data_end){
        return TC_ACT_SHOT;
    }

    if (!(bpf_ntohs(eth->h_proto)==ETH_P_IP)){ //not ip protocol
        return TC_ACT_OK;
    }

    ip = data+eth_off;
    ip_off+=eth_off+sizeof(*ip);
    if (data+ip_off>data_end){
        return TC_ACT_SHOT;
    }
    if (!(ip->protocol==IPPROTO_UDP)){ // not udp
        return TC_ACT_OK;
    }
    unsigned int *to_dest_ip_be32 = (unsigned int *)to_dest_ip;
    if (ip->saddr==*to_dest_ip_be32){
        udp = data+ip_off;
        udp_off=ip_off+sizeof(*udp);
        if (data+udp_off>data_end){
            return TC_ACT_SHOT;
        }

        if (bpf_ntohs(udp->source)==to_dest_port){ // 原地址和原端口匹配,表示是回包
            bpf_printk("recv sip %d, sport %d",bpf_ntohl(ip->saddr),bpf_ntohs(udp->source));

            int saddr_off = eth_off+offsetof(struct iphdr,saddr);
            int source_port_off = ip_off+offsetof(struct udphdr,source);
            unsigned int old_ip_saddr = ip->saddr;

             //change source ip
            unsigned int *origin_dest_ip_int = (unsigned int*)dest_ip;
            bpf_l3_csum_replace(skb,eth_off+offsetof(struct iphdr, check),old_ip_saddr,*origin_dest_ip_int,4);
            bpf_skb_store_bytes(skb,saddr_off,(void*)origin_dest_ip_int,4,0);


            //change source port
            unsigned short origin_dest_port_be = bpf_htons(dest_port);
            bpf_skb_store_bytes(skb,source_port_off,(void*)(&origin_dest_port_be),2,0);
            //这里即使不重置校验和也能成功接收数据, 原因还不明.
            int udp_csum = 0;
            bpf_skb_store_bytes(skb,ip_off+offsetof(struct udphdr, check),(void*)(&udp_csum),2,0);




            data = (void *)(unsigned long long)skb->data;
            data_end = (void *)(unsigned long long)skb->data_end;
            ip = (struct iphdr *) ((unsigned long long)data + eth_off);
            udp = (struct udphdr *) ((unsigned long long)data + ip_off);
            if (data+udp_off>data_end){
                return TC_ACT_SHOT;
            }

            bpf_printk("recv modify to_sp %d, to_sport %d",bpf_ntohl(ip->saddr),bpf_ntohs(udp->source));
        }

    }
   return TC_ACT_OK;
}


char _license[] SEC("license") = "GPL";

