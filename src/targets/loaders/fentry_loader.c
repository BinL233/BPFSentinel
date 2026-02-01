#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "loader_common.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    const char *env = getenv("LIBBPF_VERBOSE");
    if (!env || atoi(env) == 0) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

struct fentry_active {
    struct bpf_object *obj;
    struct bpf_link *link;
    char name[128];
};
static struct fentry_active fentry_list[32];
static int fentry_cnt;

static void fentry_cleanup(void)
{
    for (int i = 0; i < fentry_cnt; i++) {
        if (fentry_list[i].link) {
            bpf_link__destroy(fentry_list[i].link);
        }
        if (fentry_list[i].obj) {
            bpf_object__close(fentry_list[i].obj);
        }
    }
    fentry_cnt = 0;
}

int load_fentry_program(const char *ifname, const char *prog_name)
{
    (void)ifname;

    if (!prog_name) {
        return -EINVAL;
    }

    if (geteuid() != 0) {
        fprintf(stderr, "[fentry] must run as root to attach programs\n");
        return -EPERM;
    }

    char objpath[512];
    snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

    if (access(objpath, F_OK) != 0) {
        fprintf(stderr, "[fentry] object %s missing, skipping\n", objpath);
        return 0;
    }

    libbpf_set_print(libbpf_print_fn);

    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    int err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "[fentry] failed to open %s: %s\n", objpath, strerror(-err));
        return err;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[fentry] program '%s' not found in %s\n", prog_name, objpath);
        bpf_object__close(obj);
        return 0;
    }

    const char *sec = bpf_program__section_name(prog);
    if (!sec || strncmp(sec, "fentry/", 7) != 0) {
        fprintf(stderr, "[fentry] program '%s' has unsupported section '%s'\n", prog_name, sec ? sec : "NULL");
        bpf_object__close(obj);
        return -EINVAL;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[fentry] load failed for %s: %s\n", objpath, strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    struct bpf_link *link = bpf_program__attach(prog);
    err = libbpf_get_error(link);
    if (err) {
        fprintf(stderr, "[fentry] attach failed for section '%s': %s\n", sec, strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    printf("[fentry] attached program '%s' from section '%s' (pinning)\n", prog_name, sec);

    const char *pin_dir = "/sys/fs/bpf/links";
    mkdir(pin_dir, 0755);
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "%s/%s", pin_dir, prog_name);

    if (bpf_link__pin(link, pin_path) != 0) {
        fprintf(stderr, "[fentry] warning: failed to pin link at %s; program will go away when process exits\n", pin_path);
        if (fentry_cnt == 0) {
            atexit(fentry_cleanup);
        }

        if (fentry_cnt < (int)(sizeof(fentry_list)/sizeof(fentry_list[0]))) {
            fentry_list[fentry_cnt].obj = obj;
            fentry_list[fentry_cnt].link = link;
            strncpy(fentry_list[fentry_cnt].name, prog_name, sizeof(fentry_list[fentry_cnt].name)-1);
            fentry_list[fentry_cnt].name[sizeof(fentry_list[fentry_cnt].name)-1] = '\0';
            fentry_cnt++;
        } else {
            bpf_link__destroy(link);
            bpf_object__close(obj);
        }
    } else {
        if (fentry_cnt == 0) {
            atexit(fentry_cleanup);
        }
        if (fentry_cnt < (int)(sizeof(fentry_list)/sizeof(fentry_list[0]))) {
            fentry_list[fentry_cnt].obj = obj;
            fentry_list[fentry_cnt].link = link;
            strncpy(fentry_list[fentry_cnt].name, prog_name, sizeof(fentry_list[fentry_cnt].name)-1);
            fentry_list[fentry_cnt].name[sizeof(fentry_list[fentry_cnt].name)-1] = '\0';
            fentry_cnt++;
        }
        printf("[fentry] link pinned at %s\n", pin_path);
    }

    return 1;
}
