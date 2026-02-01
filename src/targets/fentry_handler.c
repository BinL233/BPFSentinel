// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/__x64_sys_execve")
int BPF_PROG(fentry_handler, struct pt_regs *regs)
{
    return 0;
}
