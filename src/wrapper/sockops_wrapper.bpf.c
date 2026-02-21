#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "../visor/throttle.bpf.h"
#include "wrapper.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("sockops")
int sockops_wrapper(struct bpf_sock_ops *skops)
{
    __u64 start_time = 0;
    
    // Visor Budget Check
    if (!check_budget(&start_time)) {
        // No budget available - throttle this operation
        update_stats(1, 0);
        
        bpf_printk("[Sockops Wrapper] Throttled: no budget available\n");
        
        // Return early without processing
        return 0;
    }
    
    // Budget available - dispatch to target sockops program
    bpf_tail_call(skops, &prog_array, SOCKOPS_PROG_INDEX);
    
    // Tail call failed - target not loaded
    update_stats(1, 0);
    
    return 0;
}
