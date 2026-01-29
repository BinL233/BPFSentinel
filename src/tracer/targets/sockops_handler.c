// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/tcp.h>

char LICENSE[] SEC("license") = "GPL";

/* Attach to cgroup sock_ops; op values defined in bpf_sock_ops.h */
SEC("sockops")
int sockops_handler(struct bpf_sock_ops *skops)
{
    int op = skops->op;
    bpf_printk("[SOCKOPS] op=%d\n", op);
    return 0;
}
