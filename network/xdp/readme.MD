### 这是xdp相关例子

### xdp_nat.py 

这个是xdp udp 源端口53转移到nat到127.0.0.1：1234的例子, 
效果类似于 iptables -t nat -A PREROUTING -p udp --sport 53 -j DNAT --to-destination 127.0.0.1:1234

对应类型BPF_PROG_TYPE_XDP.

xdp只能处理入网卡的包, 与tc ingress 作用与效果类似

### xdp_tx.py 
这个是数据包原路返回的例子， 把目的端口是12345（  unsigned short dport = 12345; 端口修改这行） 的包修改mac ip 端口后原路返回

## 说明
尽量不要在虚拟机上试. 用虚拟机最好接无线网卡或者其他物理网卡，不要使用虚拟机的网卡.

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

在另一台电脑上 
```bash
nc -n -v -u 192.168.1.101 12345 # 192.168.1.101 12345 改为运行ebpf的电脑xdp网卡对应的ip和 端口
```

nc那个shell 应该能看到一模一样的数据回包




