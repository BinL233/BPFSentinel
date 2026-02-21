#ifndef __THROTTLE_BPF_H__
#define __THROTTLE_BPF_H__

#include <bpf/bpf_helpers.h>
#include "throttle.h"
#include "maps.bpf.h"


static __always_inline int check_budget(__u64 *start_time)
{
    __u32 key = TOKEN_BUCKET_KEY;
    __u64 *budget_ptr;
    __u64 current_time;
    
    // Capture start time
    current_time = bpf_ktime_get_ns();
    
    // Read current budget from map
    budget_ptr = bpf_map_lookup_elem(&token_bucket, &key);
    if (!budget_ptr) {
        return 0; // Map lookup failed, throttle for safety
    }
    
    // Check if we have budget available
    if (*budget_ptr == 0) {
        return 0; // No budget remaining, throttle
    }
    
    // Store start time for later debit
    *start_time = current_time;
    return 1; // Budget available, proceed
}

static __always_inline void debit_budget(__u64 start_time)
{
    __u32 key = TOKEN_BUCKET_KEY;
    __u64 *budget_ptr;
    __u64 end_time, elapsed;
    
    // Capture end time and calculate elapsed
    end_time = bpf_ktime_get_ns();
    elapsed = end_time - start_time;
    
    // Read budget pointer
    budget_ptr = bpf_map_lookup_elem(&token_bucket, &key);
    if (!budget_ptr) {
        return; // Map lookup failed, nothing to debit
    }
    
    // Atomic subtraction to prevent race conditions
    // Ensure we don't underflow (go negative)
    if (*budget_ptr >= elapsed) {
        __sync_fetch_and_sub(budget_ptr, elapsed);
    } else {
        // Not enough budget remaining, just zero it out
        *budget_ptr = 0;
    }
}

static __always_inline void update_stats(int throttled, __u64 runtime_ns)
{
    __u32 key = STATS_KEY;
    struct throttle_stats *stats;
    
    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats) {
        return; // Map lookup failed
    }
    
    // Atomically increment total invocations
    __sync_fetch_and_add(&stats->total_invocations, 1);
    
    // Increment throttled count if applicable
    if (throttled) {
        __sync_fetch_and_add(&stats->throttled_invocations, 1);
    }
    
    // Add runtime to total if not throttled
    if (runtime_ns > 0) {
        __sync_fetch_and_add(&stats->total_runtime_ns, runtime_ns);
    }
}

#endif /* __THROTTLE_BPF_H__ */