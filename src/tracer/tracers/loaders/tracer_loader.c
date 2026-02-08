#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <limits.h>
#include "../../../utils/cJSON.h"
#include "tracer_loader.h"
#include "../printout.h"

#ifndef __cplusplus
_Static_assert(sizeof(struct trace_info) == 52, "trace_info size mismatch (expected 52 bytes)");
#endif

static volatile sig_atomic_t keep_running = 1;
unsigned long long g_event_seen = 0;
int g_print_freq = PRINTF_FREQ;

/* Track selected metrics per program type */
struct tracer_metrics_cfg g_metrics_by_prog[TRACE_PROG_SOCKOPS + 1];
unsigned char g_metrics_set[TRACE_PROG_SOCKOPS + 1];

static void sig_handler(int sig) { 
    keep_running = 0; 
}

static enum { T_NONE=0, T_XDP, T_TC, T_KPROBE, T_SOCKOPS, T_FENTRY } decide_type(const char *type_str)
{
    if (!type_str) {
        return T_NONE;
    }
    if (strcasecmp(type_str, "xdp") == 0) {
        return T_XDP;
    }
    if (strcasecmp(type_str, "tc") == 0) { 
        return T_TC;
    }
    if (strcasecmp(type_str, "kprobe") == 0) {
        return T_KPROBE;
    }
    if (strcasecmp(type_str, "sockops") == 0) {
        return T_SOCKOPS;
    }
    if (strcasecmp(type_str, "fentry") == 0) {
        return T_FENTRY;
    }
    return T_NONE;
}

enum metric_key { M_UNKNOWN=0, M_TIME, M_PKT_LEN, M_RET, M_OP };
static enum metric_key metric_from_string(const char *s) {
    if (!s || !*s) return M_UNKNOWN;
    switch (s[0]) {
    case 't':
        if (strcmp(s, "time") == 0) return M_TIME;
        break;
    case 'p':
        if (strcmp(s, "packet_len") == 0 || strcmp(s, "pkt_len") == 0) return M_PKT_LEN;
        break;
    case 'r':
        if (strcmp(s, "ret") == 0 || strcmp(s, "return_value") == 0) return M_RET;
        break;
    case 'o':
        if (strcmp(s, "op") == 0) return M_OP;
        break;
    default:
        break;
    }
    return M_UNKNOWN;
}

int main(int argc, char **argv)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *pf_env = getenv("PRINTF_FREQ");
    if (pf_env && *pf_env) {
        char *endp = NULL; long v = strtol(pf_env, &endp, 10);
        if (endp != pf_env && v > 0 && v < INT_MAX) {
            g_print_freq = (int)v;
        }
    }
    printf("[tracer-loader] PRINTF_FREQ=%d (printing 1 of every %d events)\n", g_print_freq, g_print_freq);

    const char *config_path = "../configs/config.json";
    if (argc > 1) {
        config_path = argv[1];
    }

    FILE *fp = fopen(config_path, "rb");

    if (!fp) {
        fprintf(stderr, "[tracer-loader] cannot open %s\n", config_path);
        return 1;
    }

    fseek(fp, 0, SEEK_END); 
    long fsz = ftell(fp); 
    fseek(fp, 0, SEEK_SET);
    char *buf = (char*)malloc((size_t)fsz + 1);

    if (!buf) {
        fclose(fp);
        fprintf(stderr, "OOM\n");
        return 1;
    }

    if (fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz) {
        fclose(fp);
        free(buf);
        fprintf(stderr, "read fail\n");
        return 1;
    }

    buf[fsz] = '\0'; fclose(fp);

    cJSON *root = cJSON_Parse(buf); free(buf);
    if (!root) {
        fprintf(stderr, "[tracer-loader] parse %s failed\n", config_path);
        return 1;
    }

    cJSON *targets = cJSON_GetObjectItemCaseSensitive(root, "targets");
    if (!targets || !cJSON_IsArray(targets)) {
        fprintf(stderr, "[tracer-loader] 'targets' missing\n");
        cJSON_Delete(root);
        return 1;
    }

    int n = cJSON_GetArraySize(targets);
    printf("[tracer-loader] processing %d target(s) from %s\n", n, config_path);
    int xdp_links_total=0, tc_links_total=0, kprobe_links_total=0, sockops_links_total=0, fentry_links_total=0, skipped=0;

    for (int i=0; i<n; i++) {
        cJSON *t = cJSON_GetArrayItem(targets, i);
        if (!t || !cJSON_IsObject(t)) {
            continue;
        }

        cJSON *jname = cJSON_GetObjectItemCaseSensitive(t, "name");
        cJSON *jtype = cJSON_GetObjectItemCaseSensitive(t, "type");
        cJSON *jobj  = cJSON_GetObjectItemCaseSensitive(t, "tracer_object");
        cJSON *jfentry = cJSON_GetObjectItemCaseSensitive(t, "fentry_name");
        cJSON *jfexit  = cJSON_GetObjectItemCaseSensitive(t, "fexit_name");
        cJSON *jmetrics = cJSON_GetObjectItemCaseSensitive(t, "metrics");

        if (!jname || !cJSON_IsString(jname) || !jtype || !cJSON_IsString(jtype) ||
            !jobj || !cJSON_IsString(jobj) ||
            !jfentry || !cJSON_IsString(jfentry) || !jfexit || !cJSON_IsString(jfexit) ||
            !jmetrics || !cJSON_IsArray(jmetrics)) {

            fprintf(stderr, "    [%d] invalid entry; skipping.\n", i);
            continue;
        }

        const char *tname = jname->valuestring;
        const char *ttype = jtype->valuestring;
        const char *tobj  = jobj->valuestring;
        const char *fentry_name = jfentry->valuestring;
        const char *fexit_name  = jfexit->valuestring;

        struct tracer_metrics_cfg metrics = {0};
        int msz = cJSON_GetArraySize(jmetrics);

        for (int mi = 0; mi < msz; mi++) {
            cJSON *m = cJSON_GetArrayItem(jmetrics, mi);
            if (!m || !cJSON_IsString(m) || !m->valuestring)
                continue;
            switch (metric_from_string(m->valuestring)) {
            case M_TIME:
                metrics.want_time = 1;
                break;
            case M_PKT_LEN:
                metrics.want_pkt_len = 1;
                break;
            case M_RET:
                metrics.want_ret = 1;
                break;
            case M_OP:
                metrics.want_op = 1;
                break;
            default:
                break; /* unknown metric ignored */
            }
        }

        int type = decide_type(ttype);
        switch (type) {
        case T_XDP: {
            int links = load_xdp_tracer(tname, tobj, fentry_name, fexit_name, &metrics);
            if (links > 0) {
                xdp_links_total += links;
                g_metrics_by_prog[TRACE_PROG_XDP] = metrics;
                g_metrics_set[TRACE_PROG_XDP] = 1;
            }
            break; 
        }
        case T_TC: {
            int links = load_tc_tracer(tname, tobj, fentry_name, fexit_name, &metrics);
            if (links > 0) {
                tc_links_total += links;
                g_metrics_by_prog[TRACE_PROG_TC] = metrics;
                g_metrics_set[TRACE_PROG_TC] = 1;
            }
            break; 
        }
        case T_KPROBE: {
            int links = load_kprobe_tracer(tname, tobj, fentry_name, fexit_name, &metrics);
            if (links > 0) {
                kprobe_links_total += links;
                g_metrics_by_prog[TRACE_PROG_KPROBE] = metrics;
                g_metrics_set[TRACE_PROG_KPROBE] = 1;
            }
            break;
        }
        case T_SOCKOPS: {
            int links = load_sockops_tracer(tname, tobj, fentry_name, fexit_name, &metrics);
            if (links > 0) {
                sockops_links_total += links;
                g_metrics_by_prog[TRACE_PROG_SOCKOPS] = metrics;
                g_metrics_set[TRACE_PROG_SOCKOPS] = 1;
            }
            break;
        }
        case T_FENTRY: {
            int links = load_fentry_tracer(tname, tobj, fentry_name, fexit_name, &metrics);
            if (links > 0) {
                fentry_links_total += links;
                g_metrics_by_prog[TRACE_PROG_FENTRY] = metrics;
                g_metrics_set[TRACE_PROG_FENTRY] = 1;
            }
            break;
        }
        default:
            printf("    [%d] skipping '%s' (type='%s' unsupported)\n", i, tname, ttype);
            skipped++;
            break;
        }
    }

    cJSON_Delete(root);

    printf("[tracer-loader] summary: xdp_links=%d tc_tracer_links=%d kprobe_tracer_links=%d sockops_tracer_links=%d fentry_tracer_links=%d skipped=%d\n", xdp_links_total, tc_links_total, kprobe_links_total, sockops_links_total, fentry_links_total, skipped);

#if TRACING_LOG
    /* Ring buffer consumption setup (discover 'trace_map') */
    const char *rb_name = "trace_map";
    struct ring_buffer *rb = NULL;
    int ringbufs_added = 0;

    {
        __u32 iter = 0, next;
        while (bpf_map_get_next_id(iter, &next) == 0) {
            int fd = bpf_map_get_fd_by_id(next);

            if (fd < 0) {
                break;
            }

            struct bpf_map_info info = {}; 
            __u32 len = sizeof(info);

            if (bpf_obj_get_info_by_fd(fd, &info, &len) == 0 && info.type == BPF_MAP_TYPE_RINGBUF) {
                char name[BPF_OBJ_NAME_LEN]; 
                memset(name, 0, sizeof(name)); 
                memcpy(name, info.name, sizeof(info.name));

                if (strncmp(name, rb_name, BPF_OBJ_NAME_LEN) == 0) {
                    if (!rb) {
                        rb = ring_buffer__new(fd, printout, NULL, NULL);
                        if (!rb) { 
                            fprintf(stderr, "[tracer-loader] ring_buffer__new failed: %s\n", strerror(errno)); 
                            close(fd); 
                            break; 
                        }
                    } else {
                        int err = ring_buffer__add(rb, fd, printout, NULL);
                        if (err) { 
                            fprintf(stderr, "[tracer-loader] ring_buffer__add failed: %d\n", err); 
                            close(fd); 
                        }
                    }

                    ringbufs_added++;
                    iter = next;
                    continue;
                }
            }

            close(fd);
            iter = next;
        }
    }

    if (ringbufs_added == 0)
        fprintf(stderr, "[tracer-loader] warning: no ring buffer '%s' found; events will not stream.\n", rb_name);
    else
        printf("[tracer-loader] streaming events from %d ring buffer(s). Ctrl+C to stop.\n", ringbufs_added);
#endif

    while (keep_running) {
#if TRACING_LOG
        if (!rb) { 
            usleep(200000); 
            continue; 
        }

        int err = ring_buffer__poll(rb, 200);

        if (err == -EINTR) {
            break;
        }

        if (err < 0) { 
            fprintf(stderr, "[tracer-loader] poll error: %d\n", err); 
            break; 
        }
#else
        sleep(1);
#endif
    }

#if TRACING_LOG
    if (rb) {
        ring_buffer__free(rb);
    }
#endif

    printf("[tracer-loader] exiting.\n");
    return 0;
}