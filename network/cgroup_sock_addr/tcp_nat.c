#include<linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char daddr[4] = {220,181,38,251}; // baidu.com 的 ip
unsigned short dport =80 ;

char to_daddr[4] = {45,40,60,170}; // www.biliibili.com 的 ip
unsigned short to_dport = 443 ;

//效果类似 iptables -t nat -A OUTPUT -p tcp -d 220.181.38.251 --dport 80 --to-destination 45.40.60.170:443
int tcp_dnat(struct bpf_sock_addr *ctx){
    if (__builtin_memcmp(&ctx->user_ip4,daddr,4)!=0 || bpf_ntohs(ctx->user_port)!=dport){
        return 1;
    }
    ctx->user_ip4=*(unsigned int *)to_daddr;
    ctx->user_port=bpf_htons(to_dport);
    return 1;
}