#include "utils/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "../visor/throttle.bpf.h"
#include "wrapper.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_wrapper(struct xdp_md *ctx)
{
    __u64 start_time = 0;
    
    // Visor Budget Checks
    if (!check_budget(&start_time)) {
        // No budget available - throttle this packet
        // Update statistics to track throttled invocations
        update_stats(1, 0);
        
        bpf_printk("[XDP Wrapper] Throttled: no budget available\n");
        
        return XDP_PASS;
    }
    
    bpf_tail_call(ctx, &prog_array, XDP_PROG_INDEX);

    // Tail call failed
    update_stats(1, 0);
    
    return XDP_PASS;
}
