#ifndef __VISOR_MAPS_BPF_H__
#define __VISOR_MAPS_BPF_H__

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

#endif /* __VISOR_MAPS_BPF_H__ */
