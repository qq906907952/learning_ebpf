### 这是xdp相关例子
这个是xdp udp 源端口53转移到nat到127.0.0.1：1234的例子, 
效果类似于 iptables -t nat -A PREROUTING -p udp --sport 53 -j DNAT --to-destination 127.0.0.1:1234

对应类型BPF_PROG_TYPE_XDP.

xdp只能处理入网卡的包, 与tc ingress 作用与效果类似

尽量不要在虚拟机上试. 用虚拟机最好接无线网卡.
### 说明
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
python3 xdp.py
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






