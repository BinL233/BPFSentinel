#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "../visor/throttle.bpf.h"
#include "wrapper.bpf.h"

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_wrapper(struct __sk_buff *skb)
{
    __u64 start_time = 0;
    
    // Visor Budget Check
    if (!check_budget(&start_time)) {
        // No budget available - throttle this packet
        update_stats(1, 0);
        
        bpf_printk("[TC Wrapper] Throttled: no budget available\n");
        
        // Return TC_ACT_OK to accept packet without processing
        return TC_ACT_OK;
    }
    
    // Budget available - dispatch to target TC program
    bpf_tail_call(skb, &prog_array, TC_PROG_INDEX);
    
    // Tail call failed - target not loaded
    update_stats(1, 0);
    
    // Accept packet without processing
    return TC_ACT_OK;
}
