#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "loader_common.h"

struct sockops_active {
    struct bpf_object *obj;
    char name[128];
};
static struct sockops_active sockops_list[32];
static int sockops_cnt;

static void sockops_cleanup(void)
{
    for (int i = 0; i < sockops_cnt; i++) {
        if (sockops_list[i].obj)
            bpf_object__close(sockops_list[i].obj);
    }
    sockops_cnt = 0;
}

/* Attach sockops program to a cgroup. Uses /sys/fs/cgroup or $SOCKOPS_CGROUP_PATH */
int load_sockops_program(const char *ifname, const char *prog_name)
{
    (void)ifname; /* Interface not used */

    if (!prog_name)
        return -EINVAL;

    if (geteuid() != 0) {
        fprintf(stderr, "[sockops] must run as root to attach\n");
        return -EPERM;
    }

    char objpath[512];
    snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

    if (access(objpath, F_OK) != 0) {
        fprintf(stderr, "[sockops] object %s missing, skipping\n", objpath);
        return 0; /* skip */
    }

    struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
    int err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "[sockops] open %s failed: %s\n", objpath, strerror(-err));
        return err;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[sockops] program '%s' not found in %s\n", prog_name, objpath);
        bpf_object__close(obj);
        return 0; /* treat as skip */
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "[sockops] load failed: %s\n", strerror(-err));
        bpf_object__close(obj);
        return err;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[sockops] invalid fd for '%s'\n", prog_name);
        bpf_object__close(obj);
        return -EINVAL;
    }

    const char *cgroup_path = getenv("SOCKOPS_CGROUP_PATH");
    if (!cgroup_path || !*cgroup_path) {
        cgroup_path = "/sys/fs/cgroup"; /* default */
    }

    int cg_fd = open(cgroup_path, O_DIRECTORY | O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "[sockops] open cgroup %s failed: %s\n", cgroup_path, strerror(errno));
        bpf_object__close(obj);
        return -errno;
    }

    err = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    close(cg_fd);
    if (err) {
        fprintf(stderr, "[sockops] attach failed: %s (err=%d)\n", strerror(-err), err);
        bpf_object__close(obj);
        return err;
    }

    printf("[sockops] attached '%s' to cgroup %s\n", prog_name, cgroup_path);

    if (sockops_cnt == 0)
        atexit(sockops_cleanup);
    if (sockops_cnt < (int)(sizeof(sockops_list)/sizeof(sockops_list[0]))) {
        sockops_list[sockops_cnt].obj = obj;
        strncpy(sockops_list[sockops_cnt].name, prog_name, sizeof(sockops_list[sockops_cnt].name)-1);
        sockops_list[sockops_cnt].name[sizeof(sockops_list[sockops_cnt].name)-1] = '\0';
        sockops_cnt++;
    } else {
        bpf_object__close(obj);
    }
    return 1;
}
