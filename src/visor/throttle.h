#ifndef __THROTTLE_H__
#define __THROTTLE_H__

// This header is shared between BPF programs and userspace
// BPF programs should include vmlinux.h or linux/types.h before this
// Userspace should include stdint.h or linux/types.h before this

// Token bucket configuration
#define TOKEN_BUCKET_KEY 0
#define COMPUTE_LIMIT_PCT 5  // 5% of CPU
#define REFILL_INTERVAL_NS 1000000000ULL  // 1 second in nanoseconds
#define BUDGET_PER_INTERVAL_NS (REFILL_INTERVAL_NS * COMPUTE_LIMIT_PCT / 100)  // 50ms

// Statistics tracking
struct throttle_stats {
    __u64 total_invocations;     // Total number of program invocations
    __u64 throttled_invocations; // Number of times throttled
    __u64 total_runtime_ns;      // Total execution time
    __u64 last_refill_time_ns;   // Last time budget was refilled
};

#define STATS_KEY 0

#endif
