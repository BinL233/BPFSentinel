// SPDX-License-Identifier: GPL-2.0
/*
 * Example: Integrating throttling into existing XDP program
 * This shows how to add compute throttling to xdp_handler.c
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "../visor/throttle.h"

char LICENSE[] SEC("license") = "GPL";

// Token bucket map - stores remaining nanoseconds of compute budget
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} token_bucket SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct throttle_stats);
} stats_map SEC(".maps");

// Helper functions for throttling
static __always_inline int check_budget(__u64 *elapsed_ns)
{
    __u32 key = TOKEN_BUCKET_KEY;
    __u64 *budget_ptr;
    __u64 start_time;
    
    start_time = bpf_ktime_get_ns();
    
    budget_ptr = bpf_map_lookup_elem(&token_bucket, &key);
    if (!budget_ptr || *budget_ptr == 0) {
        return 0; // No budget, throttle
    }
    
    *elapsed_ns = start_time;
    return 1; // Proceed
}

static __always_inline void debit_budget(__u64 start_time)
{
    __u32 key = TOKEN_BUCKET_KEY;
    __u64 *budget_ptr;
    __u64 end_time, elapsed;
    
    end_time = bpf_ktime_get_ns();
    elapsed = end_time - start_time;
    
    budget_ptr = bpf_map_lookup_elem(&token_bucket, &key);
    if (budget_ptr) {
        if (*budget_ptr >= elapsed) {
            __sync_fetch_and_sub(budget_ptr, elapsed);
        } else {
            *budget_ptr = 0;
        }
    }
}

static __always_inline void update_stats(int throttled, __u64 runtime_ns)
{
    __u32 key = STATS_KEY;
    struct throttle_stats *stats;
    
    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->total_invocations, 1);
        if (throttled) {
            __sync_fetch_and_add(&stats->throttled_invocations, 1);
        }
        if (runtime_ns > 0) {
            __sync_fetch_and_add(&stats->total_runtime_ns, runtime_ns);
        }
    }
}

// Original XDP handler logic with throttling added
SEC("xdp")
int xdp_handler_throttled(struct xdp_md *ctx)
{
    __u64 start_time = 0;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // ===== THROTTLING CHECK =====
    // Check budget before processing
    if (!check_budget(&start_time)) {
        // Over budget, update stats and return early
        update_stats(1, 0);
        return XDP_PASS;  // Pass packets without processing
    }
    // ============================
    
    // Original program logic
    // (commented out in original, but this is where it would be)
    // __u32 pkt_len = data_end - data;
    // bpf_printk("[XDP] Packet received, length: %u bytes\n", pkt_len);
    
    // ===== BUDGET DEBIT =====
    // Debit the budget after execution
    debit_budget(start_time);
    
    __u64 end_time = bpf_ktime_get_ns();
    update_stats(0, end_time - start_time);
    // ========================
    
    return XDP_PASS;
}

/* 
 * Integration Steps:
 * 
 * 1. Add throttle.h include
 * 2. Add token_bucket and stats_map definitions
 * 3. Add helper functions (check_budget, debit_budget, update_stats)
 * 4. Wrap main logic with:
 *    - check_budget() at start
 *    - debit_budget() at end
 *    - update_stats() for both throttled and normal cases
 * 
 * 5. Start visor_controller to manage the bucket
 * 6. Monitor statistics and CPU usage
 */
