#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../visor/throttle.bpf.h"
#include "wrapper.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("fentry/GENERIC")
int BPF_PROG(fentry_wrapper)
{
    __u64 start_time = 0;
    
    // Visor Budget Check
    if (!check_budget(&start_time)) {
        // No budget available - throttle this trace
        update_stats(1, 0);
        
        bpf_printk("[Fentry Wrapper] Throttled: no budget available\n");
        
        // Return early without tracing
        return 0;
    }
    
    bpf_tail_call(ctx, &prog_array, FENTRY_PROG_INDEX);
    
    // Tail call failed - target not loaded
    update_stats(1, 0);
    
    return 0;
}
