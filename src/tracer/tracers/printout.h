#ifndef ON_SAMPLE_H
#define ON_SAMPLE_H

#include <stddef.h>
#include <stdio.h>
#include "loaders/tracer_loader.h"

extern unsigned long long g_event_seen;
extern int g_print_freq;
extern struct tracer_metrics_cfg g_metrics_by_prog[TRACE_PROG_SOCKOPS + 1];
extern unsigned char g_metrics_set[TRACE_PROG_SOCKOPS + 1];

static inline int printout(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct trace_info)) {
        return 0;
    }
    struct trace_info *ti = (struct trace_info *)data;
    g_event_seen++;
    if (g_print_freq > 0 && (g_event_seen % g_print_freq) == 0) {
        const struct tracer_metrics_cfg *mc = NULL;
        if (ti->prog_type <= TRACE_PROG_SOCKOPS && g_metrics_set[ti->prog_type]) {
            mc = &g_metrics_by_prog[ti->prog_type];
        }

        switch (ti->prog_type) {
            case TRACE_PROG_XDP: {
                printf("[XDP] id=%llu prog_id=%u", (unsigned long long)ti->id, (unsigned int)ti->prog_id);
                if (!mc) {
                    printf(" ret=%u pkt_len=%u dur_ns=%llu start_ns=%llu\n",
                           (unsigned int)ti->ret,
                           (unsigned int)ti->pkt_len,
                           (unsigned long long)ti->duration_ns,
                           (unsigned long long)ti->start_ns);
                } else {
                    if (mc->want_ret) {
                        printf(" ret=%u", (unsigned int)ti->ret);
                    }
                    if (mc->want_pkt_len) {
                        printf(" pkt_len=%u", (unsigned int)ti->pkt_len);
                    }
                    if (mc->want_time) {
                        printf(" dur_ns=%llu start_ns=%llu",
                               (unsigned long long)ti->duration_ns,
                               (unsigned long long)ti->start_ns);
                    }
                    printf("\n");
                }
                break;
            }
            case TRACE_PROG_TC: {
                printf("[TC] id=%llu prog_id=%u", (unsigned long long)ti->id, (unsigned int)ti->prog_id);
                if (!mc) {
                    printf(" ret=%u pkt_len=%u dur_ns=%llu start_ns=%llu\n",
                           (unsigned int)ti->ret,
                           (unsigned int)ti->pkt_len,
                           (unsigned long long)ti->duration_ns,
                           (unsigned long long)ti->start_ns);
                } else {
                    if (mc->want_ret) {
                        printf(" ret=%u", (unsigned int)ti->ret);
                    }
                    if (mc->want_pkt_len) {
                        printf(" pkt_len=%u", (unsigned int)ti->pkt_len);
                    }
                    if (mc->want_time) {
                        printf(" dur_ns=%llu start_ns=%llu",
                               (unsigned long long)ti->duration_ns,
                               (unsigned long long)ti->start_ns);
                    }
                    printf("\n");
                }
                break;
            }
            case TRACE_PROG_KPROBE: {
                printf("[KPROBE] id=%llu prog_id=%u", (unsigned long long)ti->id, (unsigned int)ti->prog_id);
                if (!mc) {
                    printf(" ret=%u dur_ns=%llu start_ns=%llu\n",
                           (unsigned int)ti->ret,
                           (unsigned long long)ti->duration_ns,
                           (unsigned long long)ti->start_ns);
                } else {
                    if (mc->want_ret) {
                        printf(" ret=%u", (unsigned int)ti->ret);
                    }
                    if (mc->want_time) {
                        printf(" dur_ns=%llu start_ns=%llu",
                               (unsigned long long)ti->duration_ns,
                               (unsigned long long)ti->start_ns);
                    }
                    printf("\n");
                }
                break;
            }
            case TRACE_PROG_FENTRY: {
                printf("[FENTRY] id=%llu prog_id=%u", (unsigned long long)ti->id, (unsigned int)ti->prog_id);
                if (!mc) {
                    printf(" ret=%lld dur_ns=%llu start_ns=%llu\n",
                           (long long)ti->ret,
                           (unsigned long long)ti->duration_ns,
                           (unsigned long long)ti->start_ns);
                } else {
                    if (mc->want_ret) {
                        printf(" ret=%lld", (long long)ti->ret);
                    }
                    if (mc->want_time) {
                        printf(" dur_ns=%llu start_ns=%llu",
                               (unsigned long long)ti->duration_ns,
                               (unsigned long long)ti->start_ns);
                    }
                    printf("\n");
                }
                break;
            }
            case TRACE_PROG_SOCKOPS: {
                printf("[SOCKOPS] id=%llu prog_id=%u", (unsigned long long)ti->id, (unsigned int)ti->prog_id);
                if (!mc) {
                    printf(" ret=%u dur_ns=%llu start_ns=%llu\n",
                           (unsigned int)ti->ret,
                           (unsigned long long)ti->duration_ns,
                           (unsigned long long)ti->start_ns);
                } else {
                    if (mc->want_ret) {
                        printf(" ret=%u", (unsigned int)ti->ret);
                    }
                    if (mc->want_op) {
                        printf(" op=%u", (unsigned int)ti->op);
                    }
                    if (mc->want_time) {
                        printf(" dur_ns=%llu start_ns=%llu",
                               (unsigned long long)ti->duration_ns,
                               (unsigned long long)ti->start_ns);
                    }
                    printf("\n");
                }
                break;
            }
            default:
                printf("[UNKNOWN] id=%llu\n",
                        (unsigned long long)ti->id);
                break;
        }
    }
    return 0;
}

#endif