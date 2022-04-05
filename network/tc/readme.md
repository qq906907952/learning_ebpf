## 这里是tc相关的例子
tc主要hook点在 tc ingress 和 tc egress, 对应的程序类型是BPF_PROG_TYPE_SCHED_CLS.

可以对数据包进行编辑, 实现dnat snat等效果. tc是包级别的处理, 典型的应用就是 cilium 替换kube-proxy 用于nodePort转发

### 相关参考链接
tc的基础 可以参考 https://tonydeng.github.io/sdn-handbook/linux/tc.html

tc ebpf 相关简单的例子 参考 https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/

tc ebpf 在k8s中用于替代kube-proxy 做代理的例子 https://arthurchiao.art/blog/cracking-k8s-node-proxy/#7-implementation-4-proxy-via-tc-level-ebpf

### 相关说明
修改udp_nat.c 这个文件的 dest_ip  dest_port to_dest_ip  to_dest_port 四个变量. 
```
就是这4行
unsigned char  dest_ip[4] = {114,114,114,114};
unsigned short dest_port = 1234;
unsigned char  to_dest_ip[4] = {192,168,2,76};
unsigned short to_dest_port = 12345;
```
注意nat后的地址不能走其他网卡出去, 即$dest_ip和$to_dest_ip需要走同样路由. 例如 127.0.0.1 nat 到 114.114.114.114, 
由于会发到lo网卡,对方是接收不到的.


在tc目录下: 

编译
```bash
./compile.sh
```

加载 ebpf 到对应网卡 ($dev 改成对应网卡)
```bash
./tc_qdisc.sh $dev
```
测试
```bash
#在目的地址的机器上
socat -d -d -d udp-listen:$to_dest_port,bind=$to_dest_ip -

#本机上
socat -d -d -d udp:$dest_ip:$dest_port -
```

清理
```bash
tc qdisc delete dev $dev clsact
```



