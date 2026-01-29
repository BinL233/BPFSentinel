#ifndef LOADER_COMMON_H
#define LOADER_COMMON_H

int load_xdp_program(const char *ifname, const char *prog_name);
int load_tc_program(const char *ifname, const char *prog_name);
int load_kprobe_program(const char *ifname, const char *prog_name);
int load_sockops_program(const char *ifname, const char *prog_name);
int load_fentry_program(const char *ifname, const char *prog_name);

#endif
