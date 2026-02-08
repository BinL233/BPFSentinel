#define TRACE_PROG_NONE     0
#define TRACE_PROG_XDP      1
#define TRACE_PROG_TC       2
#define TRACE_PROG_KPROBE   3
#define TRACE_PROG_FENTRY   4
#define TRACE_PROG_SOCKOPS  5

struct trace_info {
    __u64 start_ns;
    __u64 duration_ns;
    __u32 pkt_len;
    __s64 ret;
    __u32 id;
    __u32 prog_type;
    __u32 op;
    __u32 prog_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} trace_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct trace_info);
} trace_work SEC(".maps");

struct seq_counter { 
    __u64 next_id; 
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct seq_counter);
} event_seq SEC(".maps");

/* Metrics selection configured by userspace (one entry at key 0) */
struct metrics_config {
    __u32 enable_time;
    __u32 enable_pkt_len;
    __u32 enable_ret;
    __u32 enable_op;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metrics_config);
} metrics_cfg SEC(".maps");
