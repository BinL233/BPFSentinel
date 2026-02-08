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
	if (!env || atoi(env) == 0) {
		return 0;
	}
	(void)level;
	return vfprintf(stderr, fmt, args);
}

/* Find first loaded TRACING program (fentry/fexit) whose name has given prefix */
static int find_tracing_prog_fd_by_name_prefix(const char *name_prefix)
{
	char pin_path[256];
	struct bpf_link_info linfo = {};
	__u32 link_info_len = sizeof(linfo);

	snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/links/%s", name_prefix);
	int link_fd = bpf_obj_get(pin_path);
	if (link_fd >= 0) {
		memset(&linfo, 0, sizeof(linfo));
		link_info_len = sizeof(linfo);
		if (bpf_obj_get_info_by_fd(link_fd, &linfo, &link_info_len) == 0 && linfo.prog_id) {
			int pfd = bpf_prog_get_fd_by_id(linfo.prog_id);
			close(link_fd);
			if (pfd >= 0) {
				return pfd;
			}
		}
		close(link_fd);
	}

	__u32 id = 0, next_id;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);

	while (bpf_prog_get_next_id(id, &next_id) == 0) {
		int fd = bpf_prog_get_fd_by_id(next_id);
		if (fd < 0) {
			break;
		}
		memset(&info, 0, sizeof(info));
		info_len = sizeof(info);

        // Filter bpf: We only wanna TRACING programs
		if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
			if (info.type == BPF_PROG_TYPE_TRACING) {
				size_t iname_len = strnlen((const char*)info.name, sizeof(info.name));
				size_t prefix_len = strnlen(name_prefix, 256);
				if (iname_len >= prefix_len && prefix_len > 0 &&
					strncmp((const char*)info.name, name_prefix, prefix_len) == 0) {
					return fd; /* caller closes */
				}
			}
		}
		close(fd);
		id = next_id;
	}
	return -1;
}

/* Read the kernel function name a target fentry program attaches to by
 * inspecting the section name in its object file: "fentry/<func>".
 */
static int get_fentry_target_func(const char *prog_name, char *func_buf, size_t func_buf_sz)
{
	if (!prog_name || !func_buf || func_buf_sz == 0) {
		return -EINVAL;
	}

	char objpath[512];
	memset(objpath, 0, sizeof(objpath));
	snprintf(objpath, sizeof(objpath), ".output/%s.o", prog_name);

	struct bpf_object *obj = bpf_object__open_file(objpath, NULL);
	if (libbpf_get_error(obj)) {
		return -ENOENT;
	}

	struct bpf_program *p = bpf_object__find_program_by_name(obj, prog_name);
	if (!p) {
		bpf_object__close(obj);
		return -ENOENT;
	}

	const char *sec = bpf_program__section_name(p);
	if (!sec) {
		bpf_object__close(obj);
		return -EINVAL;
	}

	const char *prefix = "fentry/";
	size_t plen = strlen(prefix);
	if (strncmp(sec, prefix, plen) != 0) {
		bpf_object__close(obj);
		return -EINVAL;
	}

	const char *fname = sec + plen;
	if (!*fname) {
		bpf_object__close(obj);
		return -EINVAL;
	}

	snprintf(func_buf, func_buf_sz, "%s", fname);
	bpf_object__close(obj);
	return 0;
}

int load_fentry_tracer(const char *target_name,
					   const char *tracer_object_path,
					   const char *fentry_name,
					   const char *fexit_name,
					   const struct tracer_metrics_cfg *metrics)
{
	if (!target_name || !tracer_object_path || !fentry_name || !fexit_name || !metrics) {
		return -EINVAL;
	}

	libbpf_set_print(libbpf_print_fn);

	int target_fd = find_tracing_prog_fd_by_name_prefix(target_name);
	if (target_fd < 0) {
		fprintf(stderr, "    [fentry-tracer] target '%s' not found; ensure fentry program is loaded and named accordingly.\n", target_name);
		return 0;
	}

	/* Get target program ID */
	struct bpf_prog_info target_info = {};
	__u32 target_info_len = sizeof(target_info);
	__u32 target_prog_id = 0;
	if (bpf_obj_get_info_by_fd(target_fd, &target_info, &target_info_len) == 0) {
		target_prog_id = target_info.id;
		fprintf(stderr, "    [fentry-tracer] target '%s' has ID %u\n", target_name, target_prog_id);
	}

	/* Derive kernel function name from the target object's section. */
	char kfunc[256];
	memset(kfunc, 0, sizeof(kfunc));
	int gret = get_fentry_target_func(target_name, kfunc, sizeof(kfunc));
	if (gret != 0) {
		fprintf(stderr, "    [fentry-tracer] cannot determine kernel function for '%s' (sec fentry/...).\n", target_name);
		close(target_fd);
		return 0;
	}

	struct bpf_object *obj = bpf_object__open_file(tracer_object_path, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "    [fentry-tracer] failed to open %s\n", tracer_object_path);
		close(target_fd);
		return -1;
	}

	struct bpf_program *fentry_prog = bpf_object__find_program_by_name(obj, fentry_name);
	struct bpf_program *fexit_prog  = bpf_object__find_program_by_name(obj, fexit_name);
	if (!fentry_prog || !fexit_prog) {
		fprintf(stderr, "    [fentry-tracer] missing tracer programs in %s\n", tracer_object_path);
		bpf_object__close(obj);
		close(target_fd);
		return -1;
	}

	/* Attach our tracer directly to the kernel function, not to the BPF fentry program. */
	bpf_program__set_attach_target(fentry_prog, 0, kfunc);
	bpf_program__set_attach_target(fexit_prog, 0, kfunc);

	int err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "    [fentry-tracer] load failed for %s: %d\n", tracer_object_path, err);
		bpf_object__close(obj);
		close(target_fd);
		return -1;
	}

	struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "metrics_cfg");
	if (cfg_map) {
		int cfg_fd = bpf_map__fd(cfg_map);
		struct { unsigned int enable_time, enable_pkt_len, enable_ret, enable_op, target_prog_id; } cfg = {0};
		cfg.enable_time = metrics->want_time;
		cfg.enable_pkt_len = 0; /* not applicable */
		cfg.enable_ret = metrics->want_ret;
		cfg.enable_op = 0;  // not used for fentry
		cfg.target_prog_id = target_prog_id;
		__u32 k = 0;
		if (bpf_map_update_elem(cfg_fd, &k, &cfg, BPF_ANY) != 0) {
			fprintf(stderr, "    [fentry-tracer] warning: failed metrics_cfg update for %s\n", target_name);
		}
	} else {
		fprintf(stderr, "    [fentry-tracer] warning: metrics_cfg map absent in %s\n", tracer_object_path);
	}

	int attached = 0;
	struct bpf_link *le = NULL, *lx = NULL;
	int need_fentry = (metrics->want_time || metrics->want_ret);
	int need_fexit  = (metrics->want_time || metrics->want_ret);

	if (need_fentry) {
		le = bpf_program__attach_trace(fentry_prog);
		if (libbpf_get_error(le)) {
			fprintf(stderr, "    [fentry-tracer] fentry attach failed (%s)\n", fentry_name);
			le = NULL;
		} else {
			attached++;
		}
	}
	if (need_fexit) {
		lx = bpf_program__attach_trace(fexit_prog);
		if (libbpf_get_error(lx)) {
			fprintf(stderr, "    [fentry-tracer] fexit attach failed (%s)\n", fexit_name);
			lx = NULL;
		} else {
			attached++;
		}
	}

    close(target_fd);
    if (attached > 0) {
        printf("    [fentry-tracer] attached to kfunc '%s' for target=%s fentry=%s fexit=%s\n",
               kfunc, target_name, need_fentry?"yes":"no", need_fexit?"yes":"no");
    } else {
        printf("    [fentry-tracer] no tracer links attached for %s\n", target_name);
        bpf_object__close(obj);
    }
    return attached;
}

