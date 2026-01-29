#ifndef TRACER_LOADER_H
#define TRACER_LOADER_H

#define TRACING_LOG 1
#define PRINTF_FREQ 1

/* Program type ids */
#define TRACE_PROG_NONE     0
#define TRACE_PROG_XDP      1
#define TRACE_PROG_TC       2
#define TRACE_PROG_KPROBE   3
#define TRACE_PROG_FENTRY   4
#define TRACE_PROG_SOCKOPS  5

struct tracer_metrics_cfg {
    int want_time;
    int want_pkt_len;
    int want_ret;
    int want_op;
};

struct trace_info {
    unsigned long long start_ns;
    unsigned long long duration_ns;
    unsigned int pkt_len;
    long long ret;
    unsigned int id;
    unsigned int prog_type;
    unsigned int op;
};

int load_xdp_tracer(const char *target_name,
                    const char *tracer_object_path,
                    const char *fentry_name,
                    const char *fexit_name,
                    const struct tracer_metrics_cfg *metrics);

int load_tc_tracer(const char *target_name,
                   const char *tracer_object_path,
                   const char *fentry_name,
                   const char *fexit_name,
                   const struct tracer_metrics_cfg *metrics);

int load_kprobe_tracer(const char *target_name,
                       const char *tracer_object_path,
                       const char *fentry_name,
                       const char *fexit_name,
                       const struct tracer_metrics_cfg *metrics);

int load_sockops_tracer(const char *target_name,
                        const char *tracer_object_path,
                        const char *fentry_name,
                        const char *fexit_name,
                        const struct tracer_metrics_cfg *metrics);

int load_sockops_tracer(const char *target_name,
                        const char *tracer_object_path,
                        const char *fentry_name,
                        const char *fexit_name,
                        const struct tracer_metrics_cfg *metrics);

int load_fentry_tracer(const char *target_name,
                       const char *tracer_object_path,
                       const char *fentry_name,
                       const char *fexit_name,
                       const struct tracer_metrics_cfg *metrics);

#endif
