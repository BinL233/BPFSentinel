/*
 * Visor Controller - User-space daemon for eBPF compute throttling
 * 
 * This daemon implements the "Doorman" architecture for eBPF programs:
 * - Refills token bucket periodically (every 1 second)
 * - Monitors actual program execution time via bpf_stats
 * - Adjusts budget dynamically to maintain 5% CPU limit
 * - Provides safety monitoring and adaptive control
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "throttle.h"

#define REFILL_INTERVAL_SEC 1
#define TARGET_CPU_PCT 5
#define ADAPTIVE_THRESHOLD_PCT 6  // Trigger adaptation if over 6%

static volatile sig_atomic_t keep_running = 1;
static int token_bucket_fd = -1;
static int stats_map_fd = -1;

// Signal handler for graceful shutdown
static void sig_handler(int signo)
{
    keep_running = 0;
}

// Enable BPF statistics in kernel
static int enable_bpf_stats(void)
{
    FILE *fp = fopen("/proc/sys/kernel/bpf_stats_enabled", "w");
    if (!fp) {
        fprintf(stderr, "Failed to open bpf_stats_enabled: %s\n", strerror(errno));
        return -1;
    }
    
    fprintf(fp, "1\n");
    fclose(fp);
    printf("[Visor] BPF statistics enabled\n");
    return 0;
}

// Get program runtime from bpftool or /proc
static int get_prog_runtime(int prog_id, unsigned long long *runtime_ns)
{
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int prog_fd;
    
    prog_fd = bpf_prog_get_fd_by_id(prog_id);
    if (prog_fd < 0) {
        return -1;
    }
    
    if (bpf_obj_get_info_by_fd(prog_fd, &info, &info_len)) {
        close(prog_fd);
        return -1;
    }
    
    *runtime_ns = info.run_time_ns;
    close(prog_fd);
    return 0;
}

// Refill the token bucket
static int refill_bucket(__u64 budget_ns)
{
    __u32 key = TOKEN_BUCKET_KEY;
    __u64 current_budget = 0;
    
    // Read current budget
    if (bpf_map_lookup_elem(token_bucket_fd, &key, &current_budget) != 0) {
        fprintf(stderr, "[Visor] Failed to read token bucket: %s\n", strerror(errno));
        return -1;
    }
    
    // Add new budget (capped at max interval budget)
    current_budget += budget_ns;
    if (current_budget > BUDGET_PER_INTERVAL_NS * 2) {
        current_budget = BUDGET_PER_INTERVAL_NS * 2;  // Cap at 2x interval to prevent accumulation
    }
    
    // Write back
    if (bpf_map_update_elem(token_bucket_fd, &key, &current_budget, BPF_ANY) != 0) {
        fprintf(stderr, "[Visor] Failed to update token bucket: %s\n", strerror(errno));
        return -1;
    }
    
    return 0;
}

// Read and display statistics
static void display_stats(void)
{
    __u32 key = STATS_KEY;
    struct throttle_stats stats = {};
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stats) != 0) {
        return;
    }
    
    if (stats.total_invocations > 0) {
        double throttle_rate = (double)stats.throttled_invocations / stats.total_invocations * 100.0;
        double avg_runtime_us = (double)stats.total_runtime_ns / stats.total_invocations / 1000.0;
        
        printf("[Visor] Stats: total=%llu, throttled=%llu (%.2f%%), avg_runtime=%.2f us\n",
               stats.total_invocations, stats.throttled_invocations, 
               throttle_rate, avg_runtime_us);
    }
}

// Adaptive budget adjustment based on actual usage
static __u64 adaptive_budget_adjustment(__u64 base_budget, int prog_id, 
                                        unsigned long long *last_runtime_ns, 
                                        time_t *last_time)
{
    unsigned long long current_runtime_ns = 0;
    time_t current_time = time(NULL);
    time_t elapsed_sec = current_time - *last_time;
    
    if (elapsed_sec < REFILL_INTERVAL_SEC) {
        return base_budget;
    }
    
    // Get current program runtime
    if (get_prog_runtime(prog_id, &current_runtime_ns) == 0) {
        unsigned long long delta_runtime = current_runtime_ns - *last_runtime_ns;
        unsigned long long wall_time_ns = elapsed_sec * 1000000000ULL;
        double actual_cpu_pct = (double)delta_runtime / wall_time_ns * 100.0;
        
        printf("[Visor] Actual CPU usage: %.2f%% (target: %d%%)\n", 
               actual_cpu_pct, TARGET_CPU_PCT);
        
        // Adaptive adjustment
        if (actual_cpu_pct > ADAPTIVE_THRESHOLD_PCT) {
            __u64 adjusted = base_budget * 0.9;  // Reduce by 10%
            printf("[Visor] WARNING: CPU usage exceeded threshold, reducing budget to %llu ns\n", 
                   adjusted);
            *last_runtime_ns = current_runtime_ns;
            *last_time = current_time;
            return adjusted;
        } else if (actual_cpu_pct < TARGET_CPU_PCT * 0.8) {
            __u64 adjusted = base_budget * 1.05;  // Increase by 5%
            if (adjusted <= BUDGET_PER_INTERVAL_NS) {
                printf("[Visor] CPU usage below target, increasing budget to %llu ns\n", adjusted);
                *last_runtime_ns = current_runtime_ns;
                *last_time = current_time;
                return adjusted;
            }
        }
        
        *last_runtime_ns = current_runtime_ns;
        *last_time = current_time;
    }
    
    return base_budget;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_map *token_map, *stats_map;
    int prog_id = -1;
    __u64 budget = BUDGET_PER_INTERVAL_NS;
    unsigned long long last_runtime_ns = 0;
    time_t last_time = time(NULL);
    int err;
    
    if (argc > 1) {
        prog_id = atoi(argv[1]);
    }
    
    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    printf("[Visor] Starting eBPF Compute Throttling Controller\n");
    printf("[Visor] Target: %d%% CPU, Budget per interval: %llu ns (%.2f ms)\n",
           TARGET_CPU_PCT, BUDGET_PER_INTERVAL_NS, 
           BUDGET_PER_INTERVAL_NS / 1000000.0);
    
    // Enable BPF statistics
    if (enable_bpf_stats() != 0) {
        fprintf(stderr, "[Visor] Warning: Could not enable BPF stats, continuing anyway\n");
    }
    
    // Load BPF object
    obj = bpf_object__open_file("throttled_prog.bpf.o", NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "[Visor] Failed to open BPF object: %s\n", strerror(-err));
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[Visor] Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }
    
    // Get map file descriptors
    token_map = bpf_object__find_map_by_name(obj, "token_bucket");
    if (!token_map) {
        fprintf(stderr, "[Visor] Failed to find token_bucket map\n");
        goto cleanup;
    }
    token_bucket_fd = bpf_map__fd(token_map);
    
    stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    if (!stats_map) {
        fprintf(stderr, "[Visor] Failed to find stats_map\n");
        goto cleanup;
    }
    stats_map_fd = bpf_map__fd(stats_map);
    
    printf("[Visor] BPF program loaded successfully\n");
    printf("[Visor] Token bucket FD: %d, Stats map FD: %d\n", 
           token_bucket_fd, stats_map_fd);
    
    // Initialize token bucket with full budget
    if (refill_bucket(BUDGET_PER_INTERVAL_NS) != 0) {
        fprintf(stderr, "[Visor] Failed to initialize token bucket\n");
        goto cleanup;
    }
    
    printf("[Visor] Controller running, refill interval: %d seconds\n", REFILL_INTERVAL_SEC);
    printf("[Visor] Press Ctrl+C to stop\n\n");
    
    // Main control loop
    while (keep_running) {
        sleep(REFILL_INTERVAL_SEC);
        
        // Adaptive budget adjustment if prog_id provided
        if (prog_id > 0) {
            budget = adaptive_budget_adjustment(budget, prog_id, 
                                               &last_runtime_ns, &last_time);
        } else {
            budget = BUDGET_PER_INTERVAL_NS;
        }
        
        // Refill the bucket
        if (refill_bucket(budget) != 0) {
            fprintf(stderr, "[Visor] Failed to refill bucket, continuing...\n");
            continue;
        }
        
        // Display statistics
        display_stats();
        
        printf("[Visor] Refilled bucket with %llu ns (%.2f ms)\n", 
               budget, budget / 1000000.0);
    }
    
    printf("\n[Visor] Shutting down controller\n");
    
cleanup:
    if (obj) {
        bpf_object__close(obj);
    }
    return 0;
}
