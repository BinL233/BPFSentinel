// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "trace_shared.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/GENERIC")
int BPF_PROG(trace_fentry_entry)
{
	__u32 zero = 0;
	struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
	int enable_time = 1, enable_ret = 1; /* no pkt len for generic handlers */
	__u32 target_prog_id = 0;
	if (cfg) {
		enable_time = cfg->enable_time;
		enable_ret = cfg->enable_ret;
		target_prog_id = cfg->target_prog_id;
	}

	__u64 work_key = bpf_get_current_pid_tgid();
	struct trace_info info = {};

	if (enable_time || enable_ret) {
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

		info.id = eid;
		info.prog_type = TRACE_PROG_FENTRY;
		info.prog_id = target_prog_id;
		bpf_map_update_elem(&trace_work, &work_key, &info, BPF_ANY);
	}
	return 0;
}

SEC("fexit/GENERIC")
int BPF_PROG(trace_fentry_exit, int ret)
{
	__u32 zero = 0;
	struct metrics_config *cfg = bpf_map_lookup_elem(&metrics_cfg, &zero);
	int enable_time = 1, enable_ret = 1;
	if (cfg) {
		enable_time = cfg->enable_time;
		enable_ret = cfg->enable_ret;
	}

	__u64 work_key = bpf_get_current_pid_tgid();
	struct trace_info *infop = bpf_map_lookup_elem(&trace_work, &work_key);

	if (!infop) {
		return 0;
	}

	if (enable_time) {
		__u64 delta = bpf_ktime_get_ns() - infop->start_ns;
		infop->duration_ns = delta;
	}

	if (enable_ret) {
		infop->ret = ctx[1];
	}

	struct trace_info *out = bpf_ringbuf_reserve(&trace_map, sizeof(*infop), 0);
	if (out) {
		__builtin_memcpy(out, infop, sizeof(*infop));
		bpf_ringbuf_submit(out, 0);
	}
	bpf_map_delete_elem(&trace_work, &work_key);
	return 0;
}

