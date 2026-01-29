#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>

#include "loader_common.h"

static int ensure_clsact(const char *ifname)
{
    /* Try adding clsact qdisc; ignore error if it already exists */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact 2>/dev/null || true", ifname);
    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "[tc] failed spawning tc (clsact)\n");
        return -1;
    }
    return 0;
}

static int attach_ingress_filter(const char *ifname, const char *objpath)
{
    /* Replace any existing ingress filter with our BPF program's 'classifier' section. */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "tc filter replace dev %s ingress prio 1 handle 1 bpf direct-action obj %s sec tc",
             ifname, objpath);
    int rc = system(cmd);
    if (rc == -1) {
        fprintf(stderr, "[tc] failed spawning tc (filter attach)\n");
        return -1;
    }
    if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0)
        return 0;
    fprintf(stderr, "[tc] tc command failed (exit=%d) while attaching %s\n", WEXITSTATUS(rc), objpath);
    return -1;
}

int load_tc_program(const char *ifname, const char *prog_name)
{
    if (!ifname || !prog_name) {
        return -EINVAL;
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "[tc] must be root to attach tc program\n");
        return -EPERM;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[tc] interface %s not found\n", ifname);
        return -1;
    }

    char objpath[512];
    snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

    if (access(objpath, F_OK) != 0) {
        fprintf(stderr, "[tc] object %s missing, skipping\n", objpath);
        return 0;
    }

    if (ensure_clsact(ifname) != 0) {
        fprintf(stderr, "[tc] cannot ensure clsact qdisc on %s\n", ifname);
        return -1;
    }

    printf("[tc] attaching tc program '%s' from %s (section 'classifier') to %s ingress\n", prog_name, objpath, ifname);

    if (attach_ingress_filter(ifname, objpath) != 0) {
        fprintf(stderr, "[tc] attach failed for %s\n", prog_name);
        return -1;
    }
    
    printf("[tc] attached tc program '%s' on %s ingress\n", prog_name, ifname);
    return 1;
}
