// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_shared.h"

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/GENERIC")
int BPF_PROG(trace_sockops_entry, struct bpf_sock_ops *skops)
{
    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_ret = 1, enable_op = 1;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_ret = cfg->enable_ret;
        enable_op = cfg->enable_op;
    }

    __u64 key = (__u64)skops;
    struct trace_info info = {};
    if (enable_time || enable_ret || enable_op) {
        if (enable_time)
            info.start_ns = bpf_ktime_get_ns();

        __u32 zero_u32 = 0; 
        __u64 eid = 0; 

        struct seq_counter *seqp = bpf_map_lookup_elem(&event_seq, &zero_u32);

        if (seqp) { 
            eid = seqp->next_id; 
            seqp->next_id++; 
        }

        info.id = eid;
        info.prog_type = TRACE_PROG_SOCKOPS;

        if (enable_op && skops) {
            __u32 op_val = 0;
            op_val = BPF_CORE_READ(skops, op);
            info.op = (__u32)op_val & 0xFF;
            bpf_printk("[TRACE] sockops_handler entry info.op:%u\n", info.op);
        }
        bpf_map_update_elem(&trace_work, &key, &info, BPF_ANY);
    }
    return 0;
}

SEC("fexit/GENERIC")
int BPF_PROG(trace_sockops_exit, struct bpf_sock_ops *skops, int ret)
{
    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_ret = 1, enable_op = 1;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_ret = cfg->enable_ret;
        enable_op = cfg->enable_op;
    }

    __u64 key = (__u64)skops;
    struct trace_info *infop = bpf_map_lookup_elem(&trace_work, &key);
    if (!infop)
        return 0;

    if (enable_time) {
        __u64 delta = bpf_ktime_get_ns() - infop->start_ns;
        infop->duration_ns = delta;
    }
    if (enable_ret) {
        infop->ret = ret;
    }


    struct trace_info *out = bpf_ringbuf_reserve(&trace_map, sizeof(*infop), 0);
    if (out) {
        __builtin_memcpy(out, infop, sizeof(*infop));
        bpf_ringbuf_submit(out, 0);
    }
    bpf_map_delete_elem(&trace_work, &key);

    // if (enable_time)
    //     bpf_printk("[TRACE] sockops_handler exit id=%llu dur_ns=%llu\n", infop->id, infop->duration_ns);
    // if (enable_ret)
    //     bpf_printk("[TRACE] sockops_handler exit id=%llu ret=%d\n", infop->id, ret);
    return 0;
}
