## ebpf 的学习记录及相关例子
鉴于ebpf的资料目前相对较少,这里整理一些学习过程中写过的例子.

ebpf学习路线比较陡峭.
bpf 总共有以下类型(下面这个枚举来自 /usr/include/linux/bpf.h)
```
enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC,
	BPF_PROG_TYPE_SOCKET_FILTER,
	BPF_PROG_TYPE_KPROBE,
	BPF_PROG_TYPE_SCHED_CLS,
	BPF_PROG_TYPE_SCHED_ACT,
	BPF_PROG_TYPE_TRACEPOINT,
	BPF_PROG_TYPE_XDP,
	BPF_PROG_TYPE_PERF_EVENT,
	BPF_PROG_TYPE_CGROUP_SKB,
	BPF_PROG_TYPE_CGROUP_SOCK,
	BPF_PROG_TYPE_LWT_IN,
	BPF_PROG_TYPE_LWT_OUT,
	BPF_PROG_TYPE_LWT_XMIT,
	BPF_PROG_TYPE_SOCK_OPS,
	BPF_PROG_TYPE_SK_SKB,
	BPF_PROG_TYPE_CGROUP_DEVICE,
	BPF_PROG_TYPE_SK_MSG,
	BPF_PROG_TYPE_RAW_TRACEPOINT,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
	BPF_PROG_TYPE_LWT_SEG6LOCAL,
	BPF_PROG_TYPE_LIRC_MODE2,
	BPF_PROG_TYPE_SK_REUSEPORT,
	BPF_PROG_TYPE_FLOW_DISSECTOR,
	BPF_PROG_TYPE_CGROUP_SYSCTL,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
	BPF_PROG_TYPE_CGROUP_SOCKOPT,
	BPF_PROG_TYPE_TRACING,
	BPF_PROG_TYPE_STRUCT_OPS,
	BPF_PROG_TYPE_EXT,
	BPF_PROG_TYPE_LSM,
	BPF_PROG_TYPE_SK_LOOKUP,
	BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
};
```
有些类型是相似的,有些是没有太大作用或者学习价值的.
我个人按照使用场景将ebpf程序分成三类

对于网络类程序, 需要熟悉协议盏,linux网络配置(先把iproute2 tc iptables 等相关命令玩熟悉).
对linux packet flow要有深刻认识 (就是这个图 https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg) ,需要知道hook点在哪里,每个hook点能做什么

对于probe类程序来说,最好了解elf结构,函数调用约定,函数调用栈结构等二进制基础知识, 最好是能看懂x86汇编.

还有一类是Perf类(貌似是用于性能监控?),这类不太了解.

ebpf有一本适合入门的书, << linux observability with bpf >>, 建议先过一次这本书.

### 环境
os:             kali linux  5.15.5-2kali2 (2021-12-22) x86_64 GNU/Linux (必须是x86_64)

bcc version:    0.22.0

libbpf version: 0.7 

能用bcc的都用bcc, bcc不好实现的(对于一些网络类ebpf bcc都不太好用), 都用clang 编译. clang 版本: Debian clang version 13.0.1-3

### 重要参考链接
https://arthurchiao.art/blog/cracking-k8s-node-proxy/#7-implementation-4-proxy-via-tc-level-ebpf

https://docs.cilium.io/en/v1.8/bpf/

### 目前已经实现的例子

#### probe类
[监听程序打开文件 类型 BPF_PROG_TYPE_TRACEPOINT](probe/open_file_log)

[ssh服务登录密码认证拦截绕过 类型 BPF_PROG_TYPE_TRACEPOINT](probe/ssh_pwd_bypass)

[hook任意程序任意指令 类型 BPF_PROG_TYPE_KPROBE ](probe/uprobe)

#### network类
[raw socket实现简单抓包. 类型 BPF_PROG_TYPE_SOCKET_FILTER](network/sock_filter)

[tc ingress 和 egress 实现简单udp nat. 类型 BPF_PROG_TYPE_SCHED_CLS](network/tc)

[xdp实现简单udp nat. 类型 BPF_PROG_TYPE_XDP](network/xdp)

[xdp实现的udp原路回包 类型 BPF_PROG_TYPE_XDP](network/xdp)

[sock addr实现简单tcp nat. 类型 BPF_PROG_TYPE_CGROUP_SOCK_ADDR](network/cgroup_sock_addr)

TODO 更多类型