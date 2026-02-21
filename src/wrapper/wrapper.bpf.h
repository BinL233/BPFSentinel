#ifndef __WRAPPER_BPF_H__
#define __WRAPPER_BPF_H__

#include "../visor/throttle.h"
#include "../visor/maps.bpf.h"

// Single prog_array map for all wrapper types
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

// Fixed indices for each wrapper type
#define XDP_PROG_INDEX     0
#define TC_PROG_INDEX      1
#define KPROBE_PROG_INDEX  2
#define SOCKOPS_PROG_INDEX 3
#define FENTRY_PROG_INDEX  4

#endif /* __WRAPPER_BPF_H__ */
