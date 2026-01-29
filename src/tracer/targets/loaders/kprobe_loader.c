#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "loader_common.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    const char *env = getenv("LIBBPF_VERBOSE");
    if (!env || atoi(env) == 0)
        return 0;
    return vfprintf(stderr, format, args);
}

struct kprobe_active {
    struct bpf_object *obj;
    struct bpf_link *link;
    char name[128];
};
static struct kprobe_active kprobe_list[32];
static int kprobe_cnt;

static void kprobe_cleanup(void)
{
    for (int i = 0; i < kprobe_cnt; i++) {
        if (kprobe_list[i].link)
            bpf_link__destroy(kprobe_list[i].link);
        if (kprobe_list[i].obj)
            bpf_object__close(kprobe_list[i].obj);
    }
    kprobe_cnt = 0;
}

int load_kprobe_program(const char *ifname, const char *prog_name)
{
    (void)ifname;

    if (!prog_name) {
        return -EINVAL;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "[kprobe] must run as root to attach probes\n");
        return -EPERM;
    }

    char objpath[512];
    snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

    if (access(objpath, F_OK) != 0) {
        fprintf(stderr, "[kprobe] object %s missing, skipping\n", objpath);
        return 0;
    }

    libbpf_set_print(libbpf_print_fn);

    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    int err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "[kprobe] failed to open %s: %s\n", objpath, strerror(-err));
        return err;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[kprobe] program '%s' not found in %s\n", prog_name, objpath);
        bpf_object__close(obj);
        return 0;
    }

    const char *sec = bpf_program__section_name(prog);
    const char *func = NULL;
    bool retprobe = false;

    if (sec && strncmp(sec, "kprobe/", 7) == 0) {
        func = sec + 7;
    } else if (sec && strncmp(sec, "kretprobe/", 10) == 0) {
        retprobe = true;
        func = sec + 10;
    } else {
        fprintf(stderr, "[kprobe] program '%s' has unsupported section '%s'\n", prog_name, sec ? sec : "NULL");
        bpf_object__close(obj);
        return -EINVAL;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[kprobe] load failed for %s: %s\n", objpath, strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    struct bpf_link *link = bpf_program__attach_kprobe(prog, retprobe, func);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "[kprobe] attach failed for section '%s': %s\n", sec, strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    printf("[kprobe] attached program '%s' from section '%s' (pinning)\n", prog_name, sec);

    const char *pin_dir = "/sys/fs/bpf/links";
    mkdir(pin_dir, 0755);
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, prog_name);

    if (bpf_link__pin(link, pin_path) != 0) {
        fprintf(stderr, "[kprobe] warning: failed to pin link at %s; kprobe will go away when process exits\n", pin_path);
        if (kprobe_cnt == 0) {
            atexit(kprobe_cleanup);
        }

        if (kprobe_cnt < (int)(sizeof(kprobe_list)/sizeof(kprobe_list[0]))) {
            kprobe_list[kprobe_cnt].obj = obj;
            kprobe_list[kprobe_cnt].link = link;

            strncpy(kprobe_list[kprobe_cnt].name, prog_name, sizeof(kprobe_list[kprobe_cnt].name)-1);

            kprobe_list[kprobe_cnt].name[sizeof(kprobe_list[kprobe_cnt].name)-1] = '\0';
            kprobe_cnt++;
        } else {
            bpf_link__destroy(link);
            bpf_object__close(obj);
        }
    } else {
        if (kprobe_cnt == 0) {
            atexit(kprobe_cleanup);
        }

        if (kprobe_cnt < (int)(sizeof(kprobe_list)/sizeof(kprobe_list[0]))) {
            kprobe_list[kprobe_cnt].obj = obj;
            kprobe_list[kprobe_cnt].link = link;

            strncpy(kprobe_list[kprobe_cnt].name, prog_name, sizeof(kprobe_list[kprobe_cnt].name)-1);

            kprobe_list[kprobe_cnt].name[sizeof(kprobe_list[kprobe_cnt].name)-1] = '\0';
            kprobe_cnt++;
        }
        printf("[kprobe] link pinned at %s\n", pin_path);
    }
    return 1;
}
