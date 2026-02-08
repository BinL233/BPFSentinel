#include "utils/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "trace_shared.h"

char LICENSE[] SEC("license") = "GPL";

// Fentry program to trace the TC program — record start time, pkt_len and id
SEC("fentry/GENERIC")
int BPF_PROG(trace_tc_entry, struct sk_buff *skb)
{
    if (!skb)
        return 0;

    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_pkt = 1, enable_ret = 1;
    __u32 target_prog_id = 0;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_pkt = cfg->enable_pkt_len;
        enable_ret = cfg->enable_ret;
        target_prog_id = cfg->target_prog_id;
    }

    __u64 work_key = (__u64)(skb);
    struct trace_info info = {};

    if (enable_time || enable_ret || enable_pkt) {

        if (enable_time) {
            info.start_ns = bpf_ktime_get_ns();
        }

        __u32 zero_u32 = 0; 
        struct seq_counter *seqp = bpf_map_lookup_elem(&event_seq, &zero_u32); 
        __u64 eid = 0; 
        
        if (seqp) { 
            eid = seqp->next_id; 
            seqp->next_id++; 
        }

        if (enable_pkt) {
            __u32 pkt_len = BPF_CORE_READ(skb, len);
            info.pkt_len = pkt_len;
        }

        info.id = eid;
        info.prog_type = TRACE_PROG_TC;
        info.prog_id = target_prog_id;
        bpf_map_update_elem(&trace_work, &work_key, &info, BPF_ANY);
        // bpf_printk("[TRACE] tc_handler entry id=%llu info.pkt_len=%u\n", eid, info.pkt_len);
    }
    return 0;
}

// Fexit program to trace when TC program exits — compute elapsed time and report id
SEC("fexit/GENERIC")
int BPF_PROG(trace_tc_exit, struct sk_buff *skb, int ret)
{
    __u32 zero = 0;
    struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
    int enable_time = 1, enable_pkt = 1, enable_ret = 1;
    if (cfg) {
        enable_time = cfg->enable_time;
        enable_pkt = cfg->enable_pkt_len;
        enable_ret = cfg->enable_ret;
    }

    __u64 work_key = (__u64)skb;
    struct trace_info *infop = bpf_map_lookup_elem(&trace_work, &work_key);
    if (!infop) {
        return 0;
    }

    if (enable_time) { 
        __u64 now = bpf_ktime_get_ns(); 
        infop->duration_ns = now - infop->start_ns; 
    }

    if (enable_ret) {
        infop->ret = ret;
    }

    struct trace_info *out = bpf_ringbuf_reserve(&trace_map, sizeof(*infop), 0);
    if (out) {
        __builtin_memcpy(out, infop, sizeof(*infop));
        bpf_ringbuf_submit(out, 0);
    }
    bpf_map_delete_elem(&trace_work, &work_key);

    // if (enable_time || enable_ret) {
    //     bpf_printk("[TRACE] tc_handler exit id=%llu dur_ns=%llu pkt_len=%llu\n", infop->id, infop->duration_ns, infop->pkt_len);
    // }
    
    return 0;
}
