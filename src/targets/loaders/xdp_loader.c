#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include "loader_common.h"
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int addattr_l(struct nlmsghdr *nlh, size_t maxlen, int type, const void *data, size_t alen)
{
    size_t len = RTA_LENGTH(alen);
    size_t newlen = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);

    if (newlen > maxlen) {
        return -1;
    }

    struct rtattr *rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = len;

    if (alen) {
        memcpy(RTA_DATA(rta), data, alen);
    }

    nlh->nlmsg_len = newlen;
    return 0;
}

static int addattr_nest(struct nlmsghdr *nlh, size_t maxlen, int type)
{
    size_t len = RTA_LENGTH(0);
    size_t newlen = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(len);

    if (newlen > maxlen) {
        return -1;
    }

    struct rtattr *rta = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));

    rta->rta_type = type;
    rta->rta_len = len;
    nlh->nlmsg_len = newlen;

    return 0;
}

static void addattr_nest_end(struct nlmsghdr *nlh, struct rtattr *nest)
{
    nest->rta_len = (char *)nlh + nlh->nlmsg_len - (char *)nest;
}

static int bpf_set_link_xdp_fd_compat(int ifindex, int fd)
{
    int sock = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE);

    if (sock < 0) {
        return -errno;
    }

    char reqbuf[256];
    memset(reqbuf, 0, sizeof(reqbuf));
    struct nlmsghdr *nlh = (struct nlmsghdr *)reqbuf;
    struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(*ifinfo));
    nlh->nlmsg_type = RTM_SETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    ifinfo->ifi_family = AF_UNSPEC;
    ifinfo->ifi_index = ifindex;

    size_t maxlen = sizeof(reqbuf);
    struct rtattr *nest = (struct rtattr *)(((char *)nlh) + NLMSG_ALIGN(nlh->nlmsg_len));

    if (addattr_nest(nlh, maxlen, IFLA_XDP) < 0) { 
        close(sock); 
        return -ENOSPC; 
    }

    if (addattr_l(nlh, maxlen, IFLA_XDP_FD, &fd, sizeof(fd)) < 0) { 
        close(sock); 
        return -ENOSPC; 
    }

    addattr_nest_end(nlh, nest);

    struct sockaddr_nl sa = { 
        .nl_family = AF_NETLINK 
    };

    int ret = sendto(sock, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa));

    if (ret < 0) { 
        int err = -errno; 
        close(sock); 
        return err; 
    }

    close(sock);
    return 0;
}

// Attach a single XDP program by its name
static int attach_named_xdp(struct bpf_object *obj, const char *prog_name, int ifindex)
{
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "    [xdp] program '%s' not found in object\n", prog_name);
        return 0;
    }
    int fd = bpf_program__fd(prog);
    if (fd < 0) {
        fprintf(stderr, "    [xdp] program '%s' has invalid fd\n", prog_name);
        return -1;
    }
    printf("    [xdp] attaching program '%s'\n", prog_name);
    int err = bpf_set_link_xdp_fd_compat(ifindex, fd);
    if (err) {
        fprintf(stderr, "    [xdp] error: attach failed: %s (err=%d)\n", strerror(-err), err);
        return -1;
    }
    return 1;
}

int load_xdp_program(const char *ifname, const char *prog_name)
{
    if (!ifname || !prog_name) {
        return -EINVAL;
    }

    int ifindex = if_nametoindex(ifname);

    if (ifindex == 0) {
        fprintf(stderr, "[xdp] interface %s not found\n", ifname);
        return -1;
    }

    char objpath[512];

    snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

    if (access(objpath, F_OK) != 0) {
        fprintf(stderr, "[xdp] object %s missing, skipping\n", objpath);
        return 0;
    }

    printf("[xdp] loading object %s\n", objpath);

    struct bpf_object *obj = bpf_object__open(objpath);

    if (libbpf_get_error(obj)) { 
        fprintf(stderr, "[xdp] open failed for %s\n", objpath); 
        return -1; 
    }

    if (bpf_object__load(obj)) { 
        fprintf(stderr, "[xdp] load failed for %s\n", objpath); 
        bpf_object__close(obj); 
        return -1; 
    }

    int attached = attach_named_xdp(obj, prog_name, ifindex);
    bpf_object__close(obj);

    if (attached <= 0) {
        printf("[xdp] no XDP program found in %s\n", objpath);
    } else {
        printf("[xdp] attached %d program(s) from %s\n", attached, objpath);
    }

    return attached;
}
