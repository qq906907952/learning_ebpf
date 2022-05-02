### 这是xdp相关例子
这里是xdp相关的例子 对应类型BPF_PROG_TYPE_XDP.

xdp只能处理入网卡的包, 与tc ingress 作用与效果类似
### xdp_nat.py
这个是xdp udp 源端口53转移到nat到127.0.0.1：1234的例子, 
效果类似于 iptables -t nat -A PREROUTING -p udp --sport 53 -j DNAT --to-destination 127.0.0.1:1234

### xdp_tx.py 
这个是数据包原路返回的例子， 把目的端口是12345（  unsigned short dport = 12345; 端口修改这行） 的包修改mac ip 端口后原路返回 对应xdp action XDP_TX

### xdp_redir.py
这个是数据包重定向到指定网卡的例子. 对应xdp action XDP_REDIRECT

ps: 这个经典的应用就是cilium用于处理nodePort的流量

## 说明
用于redir或者tx的网卡最好接无线网卡或者其他物理网卡或者veth，不要使用虚拟机的网卡.

为了能模拟入流量 最好在局域网有另一台设备发送数据（或者使用虚拟机）

### xdp_nat.py
/etc/sysctl.conf 添加下面两行
```
net.ipv4.conf.all.rp_filter=0       //关闭严格路由限制， 允许来回路由不一致
net.ipv4.conf.all.route_localnet=1  //允许外部数据路由到本地
```
执行
```bash
sysctl -p
```


修改 in_dev 改成默认路由的网卡 然后
```bash
python3 xdp_nat.py
```

再开一个shell 监听127.0.0.1 1234
```bash
nc -n v -u -l -s 127.0.0.1 -p 1234
```

然后构造一个源53端口的回包
```bash
dig baidu.com @114.114.114.114
```

nc那个shell应该能看到dns回包的数据


### xdp_tx.py 
最好使用两台电脑，连接到同一个局域网

修改 in_dev 改成对应的网卡 然后
```bash
python3 xdp_tx.py
```

在另一台电脑上发送数据
```bash
nc -n -v -u 192.168.1.101 12345 # 192.168.1.101 12345 改为运行ebpf的电脑xdp网卡对应的ip和 端口
```

nc那个shell 应该能看到一模一样的数据回包

### xdp_redir.py
这里假设宿主机网卡是eth0 ， 宿主机cni0 -> 容器 eth1 。 eth0 udp 9999端口重定向到cni0 并改成 172.17.0.2:1234

这里简单模拟一个容器网络环境, 新建一个网络命名空间，新建veth网卡， 将eth0的数据修改mac和ip地址后重定向到cni0, 发送到容器eth1(这算是cilium南北向流量极简化实现)。

新建netns和设置ip
```bash
ip netns add test
ip link add cni0 type veth peer name eth1
ip link set eth1  netns test
# ip link 能看到 cni0 ， ip netns exec test ip link 能看到 eth1 ,这里 cni0 类似docker0 ， eth1 对应容器网卡

ip addr add 172.17.0.1/24 dev cni0 # 设置ip地址 
ip netns exec test ip addr add 172.17.0.2/24 dev eth1 #设置容器ip地址

ip link set cni0 up
ip netns exec test ip link set eth1 up

#这个路由规则的目的是创建回路路由 不然nc会报Network is unreachable
#这里不能使用iptables做snat xdp会绕过整个协议盏和netfilter， 所有netfilter的规则在这里都是没有效的
ip netns exec test ip route add default via 172.17.0.1 dev eth1 

```

修改5个变量：

    in_dev 改为数据入口网卡(这里假设是eth0)
    out_dev_idx 改为要重定向的网卡index（这里是的网卡是cni0,index就是命令 ip link 对应那个数字）
    unsigned short from_dport 改成需要重定向匹配的端口（对应nodePort的端口,这里假设是9999）
    unsigned short to_dport 改成容器里监听的端口（对应service的里targetPort，这里假设是1234）
    unsigned char to_mac[6] 改为容器里eth1的mac地址

容器监听udp1234
```bash
ip netns exec test nc -l -n -v -u -p 1234
```

运行py程序
```bash
python3 xdp_redit.py
```

发送数据到eth0接口 在同一个局域网的另一台设备上执行 
```bash
nc -n -v -u 192.168.1.3 9999 #192.168.1.3 改成eth0的ip， 下面都假设eth0的ip是192.168.1.3
```
容器里的nc应该能收到相应的数据

容器要反向发送数据是不行的，因为源地址不匹配：
    
    设备 192.168.1.x:xxxxx ------> 192.168.1.3:9999 --------> 172.17.0.2:1234
               ^                                                    | 
               ^                                                    |
               |                                                    v
               |                                                    v
               |----------------<----------<------------------------|
    (这里源地址是172.17.0.2：1234,而192.168.1.x:xxxxx 只能接受源地址192.168.1.3:9999的数据)

如果要反向发送数据 需要snat（需要打开ipv4转发，sysctl.conf里将net.ipv4.ip_forward设置为1, 现实中cilium snat由ebpf处理，不使用iptables）

```bash
iptables -t nat -A POSTROUTING -p udp -s 172.17.0.2 --sport 1234 -j SNAT --to-source 192.168.1.3:9999
```















