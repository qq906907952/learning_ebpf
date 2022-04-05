## 这里是raw socket相关的例子
这是一个简单抓包的例子，对应程序类型是BPF_PROG_TYPE_SOCKET_FILTER

### 说明
修改 dev 变量 改成对应的网卡 然后执行

```bash
python3 packet_dump.py
```