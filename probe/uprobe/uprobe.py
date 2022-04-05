from bcc import BPF
import os
"""
pt_regs 结构

struct pt_regs {
	unsigned long bx;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long bp;
	unsigned long ax;
	unsigned short ds;
	unsigned short __dsh;
	unsigned short es;
	unsigned short __esh;
	unsigned short fs;
	unsigned short __fsh;
	unsigned short gs;
	unsigned short __gsh;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned short cs;
	unsigned short __csh;
	unsigned long flags;
	unsigned long sp;
	unsigned short ss;
	unsigned short __ssh;
};
"""

"""
objdump --disassemble="custom_print" test -M intel

0000000000001139 <custom_print>:
    1139:       55                      push   rbp
    113a:       48 89 e5                mov    rbp,rsp
    113d:       48 83 ec 30             sub    rsp,0x30
    1141:       48 89 7d d8             mov    QWORD PTR [rbp-0x28],rdi
    1145:       48 8b 45 d8             mov    rax,QWORD PTR [rbp-0x28]
    1149:       48 89 c6                mov    rsi,rax
    114c:       48 8d 05 b1 0e 00 00    lea    rax,[rip+0xeb1]        # 2004 <_IO_stdin_used+0x4>
    1153:       48 89 c7                mov    rdi,rax
    1156:       b8 00 00 00 00          mov    eax,0x0
    115b:       e8 d0 fe ff ff          call   1030 <printf@plt>
    1160:       48 b8 69 74 20 73 68    movabs rax,0x6c756f6873207469
    1167:       6f 75 6c 
    116a:       48 ba 64 20 70 72 69    movabs rdx,0x20746e6972702064
    1171:       6e 74 20 
    1174:       48 89 45 e0             mov    QWORD PTR [rbp-0x20],rax
    1178:       48 89 55 e8             mov    QWORD PTR [rbp-0x18],rdx
    117c:       48 b8 73 73 73 20 6e    movabs rax,0x6d726f6e20737373
    1183:       6f 72 6d 
    1186:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
    118a:       c7 45 f8 61 6c 6c 79    mov    DWORD PTR [rbp-0x8],0x796c6c61
    1191:       c6 45 fc 00             mov    BYTE PTR [rbp-0x4],0x0
    1195:       48 8d 45 e0             lea    rax,[rbp-0x20] ; [rbp-0x20] 这个rbp偏移0x20 就是 char ss[]的局部变量的地址
    1199:       48 89 c6                mov    rsi,rax
    119c:       48 8d 05 61 0e 00 00    lea    rax,[rip+0xe61]        # 2004 <_IO_stdin_used+0x4>
    11a3:       48 89 c7                mov    rdi,rax
    11a6:       b8 00 00 00 00          mov    eax,0x0
    11ab:       e8 80 fe ff ff          call   1030 <printf@plt>
    11b0:       90                      nop
    11b1:       c9                      leave  
    11b2:       c3                      ret   

"""

text = """
#include<linux/ptrace.h>

int hook_sym(struct pt_regs *ctx){
    bpf_trace_printk("enter to sym hook");
    char replace[] = "i will replace aaa str";
    unsigned char *buf_addr = (unsigned char *)(unsigned long long)ctx->di;
    bpf_probe_write_user(buf_addr,replace,sizeof(replace));
    bpf_trace_printk("%s","exit to sym hook");
    return 0;
}

int hook_addr(struct pt_regs *ctx){
    bpf_trace_printk("%s","enter to addr hook");
    char replace[] = "i will replace sss str";
    char * buf_addr = (char *)(unsigned long long)(ctx->bp - 0x20); // address of rbp - 20
    bpf_probe_write_user(buf_addr,replace,sizeof(replace));
    bpf_trace_printk("exit to addr hook");
    return 0;
}

"""

dir=os.path.dirname(__file__)
file_name = dir + "/test"
file_name_after_strip = dir + "/test_strip"

b = BPF(text=text)
# attach sym
b.attach_uprobe(file_name, sym="custom_print", fn_name="hook_sym")
# attach addr
b.attach_uprobe(file_name_after_strip, addr=0x1195, fn_name="hook_addr")
b.trace_print()
