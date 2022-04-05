### 说明
这是一个hook任意程序任意地址的例子 对应程序类型 BPF_PROG_TYPE_KPROBE

先编译
```bash
gcc  -o test ./test.c 

strip test -o test_strip # 删除所有符号

./test
./test_strip
```
能看到和源代码正确的输出

```bash 
python3 uprobe.py
```

再尝试执行

````bash
./test
./test_strip
````

输出已经被替换