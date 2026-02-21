#include "utils/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../visor/throttle.bpf.h"
#include "wrapper.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("kprobe")
int kprobe_wrapper(struct pt_regs *ctx)
{
    __u64 start_time = 0;
    
    // Visor Budget Check
    if (!check_budget(&start_time)) {
        // No budget available - throttle this probe
        update_stats(1, 0);
        
        bpf_printk("[Kprobe Wrapper] Throttled: no budget available\n");
        
        // Return early without processing
        return 0;
    }
    
    // Budget available - dispatch to target kprobe program
    bpf_tail_call(ctx, &prog_array, KPROBE_PROG_INDEX);
    
    // Tail call failed - target not loaded
    update_stats(1, 0);
    
    return 0;
}
