from bcc import BPF

text = """

// reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
// or reference  https://github.com/torvalds/linux/blob/master/tools/perf/examples/bpf/sys_enter_openat.c
struct openat_args {
    long unused;
    long syscall_nr;
    long dfd;
    char *filename_ptr;
    long flags;
    long mode;
};

// reference /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat2/format
struct openat2_args {
    long unused1;
    long syscall_nr;
    long dfd;
    char *filename_ptr;
    long unused2;
    long unused3;
};

int open_at_hook(struct openat_args * arg){
    char comm[16] ;
    bpf_get_current_comm(comm,16);
    int pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("pid %d command %s open file %s",pid,comm,arg->filename_ptr);
}

int open_at2_hook(struct openat2_args * arg){
    char comm[16] ;
    bpf_get_current_comm(comm,16);
    int pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("pid %d command %s open file %s",pid,comm,arg->filename_ptr);
}
"""

b = BPF(text=text)
b.attach_tracepoint('syscalls:sys_enter_openat',fn_name="open_at_hook")
b.attach_tracepoint('syscalls:sys_enter_openat2',fn_name="open_at2_hook")
while 1:
    (task, pid, cpu, flags, timestamp, msg) = b.trace_fields()
    print(msg)
