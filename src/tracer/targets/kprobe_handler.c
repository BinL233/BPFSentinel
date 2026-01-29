// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_execve")
int kprobe_handler(struct pt_regs *ctx)
{
    // bpf_printk("[KPROBE] exec path entered\n");
    return 1;
}
