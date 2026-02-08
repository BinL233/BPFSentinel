// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace_shared.h"
// #include "../../visor/throttle.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/GENERIC")
int BPF_PROG(trace_xdp_entry, struct xdp_buff *xdp_ctx)
{
    __u64 throttle_start_time = 0;
    
    // Check budget before proceeding
    // if (!check_budget(&throttle_start_time)) {
    //     update_stats(1, 0);
    //     return 0;
    // }

    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_pkt = 1, enable_ret = 1;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_pkt = cfg->enable_pkt_len;
        enable_ret = cfg->enable_ret;
    }

    void *data_end = xdp_ctx->data_end;
    void *data = xdp_ctx->data;
    // if (data_end <= data) {
    //     debit_budget(throttle_start_time);
    //     return 0;
    // }

    __u64 work_key = (__u64)xdp_ctx;
    struct trace_info info = {};
    if (enable_time || enable_ret || enable_pkt) {

        if (enable_time) {
            info.start_ns = bpf_ktime_get_ns();
        }

        if (enable_pkt) {
            info.pkt_len = (__u32)(data_end - data);
        }

        /* Acquire global sequence id */
        __u32 zero_u32 = 0; __u64 event_id = 0;
        struct seq_counter *seqp = bpf_map_lookup_elem(&event_seq, &zero_u32);
        if (seqp) {
            event_id = seqp->next_id;
            seqp->next_id++;
        }

        info.id = event_id;
        info.prog_type = TRACE_PROG_XDP;
        bpf_map_update_elem(&trace_work, &work_key, &info, BPF_ANY);

        // bpf_printk("[TRACE] xdp_handler entry id=%llu\n", event_id);
    }
    
    // Debit budget after execution
    // debit_budget(throttle_start_time);
    
    return 0;
}

SEC("fexit/GENERIC")
int BPF_PROG(trace_xdp_exit, struct xdp_buff *xdp_ctx, int ret)
{
    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_pkt = 1, enable_ret = 1;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_pkt = cfg->enable_pkt_len;
        enable_ret = cfg->enable_ret;
    }

    __u64 work_key = (__u64)xdp_ctx;
    struct trace_info *infop = bpf_map_lookup_elem(&trace_work, &work_key);
    if (!infop) {
        return 0;
    }

    __u64 delta = 0;
    if (enable_time) {
        __u64 now = bpf_ktime_get_ns();
        delta = now - infop->start_ns;
        infop->duration_ns = delta;
    }

    if (enable_ret) {
        infop->ret = ret;
    }

    /* Emit finalized event to ring buffer */
    struct trace_info *out = bpf_ringbuf_reserve(&trace_map, sizeof(*infop), 0);
    if (out) {
        __builtin_memcpy(out, infop, sizeof(*infop));
        bpf_ringbuf_submit(out, 0);
    }
    bpf_map_delete_elem(&trace_work, &work_key);

    // if ((enable_time || enable_ret) && infop) {
    //     bpf_printk("[TRACE] xdp_handler exit id=%llu dur_ns=%llu ret=%d\n",
    //            infop->id, infop->duration_ns, ret);
    // }
    
    // Update throttle stats
    // update_stats(0, delta);
    
    return 0;
}
