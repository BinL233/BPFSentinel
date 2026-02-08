#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tracer_loader.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    const char *env = getenv("LIBBPF_VERBOSE");
    if (!env || atoi(env) == 0)
        return 0;
    (void)level;
    return vfprintf(stderr, fmt, args);
}

/* Find a loaded TC (SCHED_CLS) program by name prefix; returns FD or -1 */
static int find_tc_prog_fd_by_name_prefix(const char *name_prefix)
{
    __u32 id = 0, next_id;
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);

    while (bpf_prog_get_next_id(id, &next_id) == 0) {
        int fd = bpf_prog_get_fd_by_id(next_id);
        if (fd < 0)
            break;

        memset(&info, 0, sizeof(info));
        info_len = sizeof(info);
        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
            if (info.type == BPF_PROG_TYPE_SCHED_CLS) {
                size_t iname_len = strnlen((const char*)info.name, sizeof(info.name));
                size_t prefix_len = strnlen(name_prefix, 256);
                if (iname_len >= prefix_len && prefix_len > 0 &&
                    strncmp((const char*)info.name, name_prefix, prefix_len) == 0) {
                    return fd; /* caller is responsible for closing fd */
                }
            }
        }

        close(fd);
        id = next_id;
    }
    return -1;
}

int load_tc_tracer(const char *target_name,
                    const char *tracer_object_path,
                    const char *fentry_name,
                    const char *fexit_name,
                    const struct tracer_metrics_cfg *metrics)
{
    if (!target_name || !tracer_object_path || !fentry_name || !fexit_name || !metrics) {
        return -EINVAL;
    }

    libbpf_set_print(libbpf_print_fn);

    int tc_prog_fd = find_tc_prog_fd_by_name_prefix(target_name);
    if (tc_prog_fd < 0) {
        fprintf(stderr, "    [tc-tracer] target '%s' not found, skipping.\n", target_name);
        return 0;
    }

    /* Get target program ID */
    struct bpf_prog_info target_info = {};
    __u32 target_info_len = sizeof(target_info);
    __u32 target_prog_id = 0;
    if (bpf_obj_get_info_by_fd(tc_prog_fd, &target_info, &target_info_len) == 0) {
        target_prog_id = target_info.id;
        fprintf(stderr, "    [tc-tracer] target has ID %u\n", target_prog_id);
    }

    struct bpf_object *obj = bpf_object__open_file(tracer_object_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "    [tc-tracer] failed to open %s\n", tracer_object_path);
        close(tc_prog_fd);
        return -1;
    }

    struct bpf_program *fentry_prog = bpf_object__find_program_by_name(obj, fentry_name);
    struct bpf_program *fexit_prog  = bpf_object__find_program_by_name(obj, fexit_name);

    if (!fentry_prog || !fexit_prog) {
        fprintf(stderr, "    [tc-tracer] missing tracer programs in %s\n", tracer_object_path);
        bpf_object__close(obj);
        close(tc_prog_fd);
        return -1;
    }

    // fprintf(stderr, "    [tc-tracer] fentry_name: %s, fexit_name: %s, target_name: %s\n", fentry_name, fexit_name, target_name);

    /* Set attach target to the live TC program */
    bpf_program__set_attach_target(fentry_prog, tc_prog_fd, target_name);
    bpf_program__set_attach_target(fexit_prog,  tc_prog_fd, target_name);

    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "    [tc-tracer] load failed for %s: %d\n", tracer_object_path, err);
        bpf_object__close(obj);
        close(tc_prog_fd);
        return -1;
    }

    /* Configure metrics map if present */
    struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "metrics_cfg");
    if (cfg_map) {
        int cfg_fd = bpf_map__fd(cfg_map);
        struct { unsigned int enable_time, enable_pkt_len, enable_ret, enable_op, target_prog_id; } cfg = {0};
        cfg.enable_time = metrics->want_time;
        cfg.enable_pkt_len = metrics->want_pkt_len;
        cfg.enable_ret = metrics->want_ret;
        cfg.enable_op = 0;  // not used for TC
        cfg.target_prog_id = target_prog_id;
        __u32 k = 0;

        if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) != 0) {
            fprintf(stderr, "    [tc-tracer] warning: failed metrics_cfg update for %s\n", target_name);
        }
    } else {
        fprintf(stderr, "    [tc-tracer] warning: metrics_cfg map absent in %s\n", tracer_object_path);
    }

    int attached = 0;
    struct bpf_link *le = NULL, *lx = NULL;
    int need_fentry = (metrics->want_time || metrics->want_pkt_len || metrics->want_ret);
    int need_fexit  = (metrics->want_time || metrics->want_ret || metrics->want_pkt_len);

    if (need_fentry) {
        le = bpf_program__attach_trace(fentry_prog);
        if (libbpf_get_error(le)) {
            fprintf(stderr, "    [tc-tracer] fentry attach failed (%s)\n", fentry_name);
            le = NULL;
        } else {
            attached++;
        }
    }

    if (need_fexit) {
        lx = bpf_program__attach_trace(fexit_prog);
        if (libbpf_get_error(lx)) {
            fprintf(stderr, "    [tc-tracer] fexit attach failed (%s)\n", fexit_name);
            lx = NULL;
        } else {
            attached++;
        }
    }

    close(tc_prog_fd);

    if (attached > 0)
        printf("    [tc-tracer] attached: target=%s fentry=%s fexit=%s\n", target_name,
                need_fentry?"yes":"no", need_fexit?"yes":"no");
    else {
        printf("    [tc-tracer] no tracer links attached for %s\n", target_name);
        bpf_object__close(obj);
    }

    return attached;
}