## 这是cgroup/sock_addr 的例子
主要用于在socket connect阶段改写connect的地址和端口 实现tcp nat. 
对应类型BPF_PROG_TYPE_CGROUP_SOCK_ADDR
### 说明
先编译
```bash
./compile.sh
```

然后加载到内核
```bash
mkdir  /tmp/ebpf_fd
bpftool prog load tcp_nat.o /tmp/ebpf_fd/tcp_nat_fd type cgroup/connect4
#查看当前loaded的bpf: prog bpftool prog show 
```

mount cgroup
```bash
mkdir -p /tmp/cgroup/nat_test
mount -t cgroup2 none /tmp/cgroup/nat_test
```

attach到cgroup
```bash
bpftool cgroup attach /tmp/cgroup/nat_test connect4 pinned /tmp/ebpf_fd/tcp_nat_fd
# 查看当前attach: bpftool cgroup show /tmp/cgroup/nat_test
```
验证
```bash
curl 220.181.38.251:80
```

clean
```bash
bpftool cgroup detach /tmp/cgroup/nat_test connect4 name tcp_dnat
rm /tmp/ebpf_fd/tcp_nat_fd
umount /tmp/cgroup/nat_test
rmdir /tmp/cgroup/nat_test
```




