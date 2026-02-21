/*
 * Wrapper Loader - Infrastructure for loading BPF wrappers with Visor budget control
 * 
 * This loader is completely separate from target loaders (tenant code).
 * It handles:
 * 1. Loading wrapper programs and attaching them
 * 2. Pinning shared visor maps (token_bucket, stats_map)
 * 3. Loading target programs (not attaching)
 * 4. Wiring tail calls from wrappers to targets
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include "../utils/cJSON.h"

// Store loaded objects to keep them alive
static struct bpf_object *xdp_wrapper_obj = NULL;
static struct bpf_object *xdp_target_obj = NULL;
static struct bpf_object *tc_wrapper_obj = NULL;
static struct bpf_object *tc_target_obj = NULL;
static struct bpf_object *kprobe_wrapper_obj = NULL;
static struct bpf_object *kprobe_target_obj = NULL;
static struct bpf_object *sockops_wrapper_obj = NULL;
static struct bpf_object *sockops_target_obj = NULL;
static struct bpf_object *fentry_wrapper_obj = NULL;
static struct bpf_object *fentry_target_obj = NULL;

// Helper to reuse or pin shared maps
static int ensure_shared_maps_pinned(struct bpf_object *obj)
{
    struct bpf_map *token_bucket = bpf_object__find_map_by_name(obj, "token_bucket");
    struct bpf_map *stats_map = bpf_object__find_map_by_name(obj, "stats_map");
    
    // Try to reuse pinned maps first
    if (access("/sys/fs/bpf/token_bucket", F_OK) == 0) {
        printf("[wrapper] reusing pinned token_bucket\n");
        if (token_bucket) {
            int fd = bpf_obj_get("/sys/fs/bpf/token_bucket");
            if (fd >= 0) {
                bpf_map__reuse_fd(token_bucket, fd);
            }
        }
    } else if (token_bucket) {
        // Pin for first time
        if (bpf_map__pin(token_bucket, "/sys/fs/bpf/token_bucket") == 0) {
            printf("[wrapper] pinned token_bucket\n");
        }
    }
    
    if (access("/sys/fs/bpf/stats_map", F_OK) == 0) {
        printf("[wrapper] reusing pinned stats_map\n");
        if (stats_map) {
            int fd = bpf_obj_get("/sys/fs/bpf/stats_map");
            if (fd >= 0) {
                bpf_map__reuse_fd(stats_map, fd);
            }
        }
    } else if (stats_map) {
        // Pin for first time
        if (bpf_map__pin(stats_map, "/sys/fs/bpf/stats_map") == 0) {
            printf("[wrapper] pinned stats_map\n");
        }
    }
    
    return 0;
}

// Load and attach XDP wrapper, wire to target
static int load_xdp_wrapper(const char *ifname, const char *target_name)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[wrapper] interface %s not found\n", ifname);
        return -1;
    }

    char wrapper_path[512], target_path[512];
    snprintf(wrapper_path, sizeof(wrapper_path), ".output/xdp_wrapper.o");
    snprintf(target_path, sizeof(target_path), ".output/%s.o", target_name);

    // Check files exist
    if (access(wrapper_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] %s not found\n", wrapper_path);
        return -1;
    }
    if (access(target_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] target %s not found\n", target_path);
        return -1;
    }

    // 1. Load wrapper
    printf("[wrapper] loading XDP wrapper\n");
    xdp_wrapper_obj = bpf_object__open(wrapper_path);
    if (libbpf_get_error(xdp_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to open XDP wrapper\n");
        return -1;
    }
    if (bpf_object__load(xdp_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to load XDP wrapper\n");
        bpf_object__close(xdp_wrapper_obj);
        xdp_wrapper_obj = NULL;
        return -1;
    }

    // 2. Attach wrapper to interface
    struct bpf_program *wrapper_prog = bpf_object__find_program_by_name(xdp_wrapper_obj, "xdp_wrapper");
    if (!wrapper_prog) {
        fprintf(stderr, "[wrapper] xdp_wrapper program not found\n");
        bpf_object__close(xdp_wrapper_obj);
        xdp_wrapper_obj = NULL;
        return -1;
    }
    
    struct bpf_link *link = bpf_program__attach_xdp(wrapper_prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "[wrapper] failed to attach XDP wrapper\n");
        bpf_object__close(xdp_wrapper_obj);
        xdp_wrapper_obj = NULL;
        return -1;
    }
    printf("[wrapper] XDP wrapper attached to %s\n", ifname);

    // 3. Pin/reuse shared maps
    ensure_shared_maps_pinned(xdp_wrapper_obj);

    // 4. Load target (don't attach)
    printf("[wrapper] loading XDP target %s (not attaching)\n", target_name);
    xdp_target_obj = bpf_object__open(target_path);
    if (libbpf_get_error(xdp_target_obj)) {
        fprintf(stderr, "[wrapper] failed to open XDP target\n");
        return -1;
    }
    if (bpf_object__load(xdp_target_obj)) {
        fprintf(stderr, "[wrapper] failed to load XDP target\n");
        bpf_object__close(xdp_target_obj);
        xdp_target_obj = NULL;
        return -1;
    }

    // 5. Get target program FD
    struct bpf_program *target_prog = bpf_object__find_program_by_name(xdp_target_obj, target_name);
    if (!target_prog) {
        fprintf(stderr, "[wrapper] target program '%s' not found\n", target_name);
        return -1;
    }
    int target_fd = bpf_program__fd(target_prog);

    // 6. Wire tail call to index 0 (XDP_PROG_INDEX)
    struct bpf_map *prog_array = bpf_object__find_map_by_name(xdp_wrapper_obj, "prog_array");
    if (!prog_array) {
        fprintf(stderr, "[wrapper] prog_array not found\n");
        return -1;
    }
    
    int prog_array_fd = bpf_map__fd(prog_array);
    __u32 key = 0;  // XDP_PROG_INDEX
    if (bpf_map_update_elem(prog_array_fd, &key, &target_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[wrapper] failed to wire tail call: %s\n", strerror(errno));
        return -1;
    }

    printf("[wrapper] XDP tail call wired: wrapper -> %s\n", target_name);
    return 0;
}

// Load and attach TC wrapper, wire to target
static int load_tc_wrapper(const char *ifname, const char *target_name)
{
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[wrapper] interface %s not found\n", ifname);
        return -1;
    }

    char wrapper_path[512], target_path[512];
    snprintf(wrapper_path, sizeof(wrapper_path), ".output/tc_wrapper.o");
    snprintf(target_path, sizeof(target_path), ".output/%s.o", target_name);

    if (access(wrapper_path, F_OK) != 0 || access(target_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] TC wrapper or target missing\n");
        return -1;
    }

    // Load wrapper
    printf("[wrapper] loading TC wrapper\n");
    tc_wrapper_obj = bpf_object__open(wrapper_path);
    if (libbpf_get_error(tc_wrapper_obj) || bpf_object__load(tc_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to load TC wrapper\n");
        return -1;
    }

    // Attach wrapper to TC
    struct bpf_program *wrapper_prog = bpf_object__find_program_by_name(tc_wrapper_obj, "tc_wrapper");
    if (!wrapper_prog) {
        fprintf(stderr, "[wrapper] tc_wrapper program not found\n");
        return -1;
    }
    
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex, .attach_point = BPF_TC_INGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1, .prog_fd = bpf_program__fd(wrapper_prog));
    
    bpf_tc_hook_create(&hook);
    if (bpf_tc_attach(&hook, &opts) < 0) {
        fprintf(stderr, "[wrapper] failed to attach TC wrapper\n");
        return -1;
    }
    printf("[wrapper] TC wrapper attached to %s\n", ifname);

    // Pin/reuse shared maps
    ensure_shared_maps_pinned(tc_wrapper_obj);

    // Load target
    printf("[wrapper] loading TC target %s\n", target_name);
    tc_target_obj = bpf_object__open(target_path);
    if (libbpf_get_error(tc_target_obj) || bpf_object__load(tc_target_obj)) {
        fprintf(stderr, "[wrapper] failed to load TC target\n");
        return -1;
    }

    // Wire tail call to index 1 (TC_PROG_INDEX)
    struct bpf_program *target_prog = bpf_object__find_program_by_name(tc_target_obj, target_name);
    if (!target_prog) {
        fprintf(stderr, "[wrapper] TC target program not found\n");
        return -1;
    }

    struct bpf_map *prog_array = bpf_object__find_map_by_name(tc_wrapper_obj, "prog_array");
    if (!prog_array) {
        fprintf(stderr, "[wrapper] prog_array not found\n");
        return -1;
    }

    __u32 key = 1;  // TC_PROG_INDEX
    int target_fd = bpf_program__fd(target_prog);
    if (bpf_map_update_elem(bpf_map__fd(prog_array), &key, &target_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[wrapper] failed to wire TC tail call\n");
        return -1;
    }

    printf("[wrapper] TC tail call wired: wrapper -> %s\n", target_name);
    return 0;
}

// Load kprobe wrapper, wire to target
static int load_kprobe_wrapper(const char *target_name)
{
    char wrapper_path[512], target_path[512];
    snprintf(wrapper_path, sizeof(wrapper_path), ".output/kprobe_wrapper.o");
    snprintf(target_path, sizeof(target_path), ".output/%s.o", target_name);

    if (access(wrapper_path, F_OK) != 0 || access(target_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] kprobe wrapper or target missing\n");
        return -1;
    }

    // Load wrapper
    printf("[wrapper] loading kprobe wrapper\n");
    kprobe_wrapper_obj = bpf_object__open(wrapper_path);
    if (libbpf_get_error(kprobe_wrapper_obj) || bpf_object__load(kprobe_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to load kprobe wrapper\n");
        return -1;
    }

    // Note: Kprobe attachment depends on specific function to probe
    // Leaving attachment for now as it requires knowing the target function

    ensure_shared_maps_pinned(kprobe_wrapper_obj);

    // Load target
    printf("[wrapper] loading kprobe target %s\n", target_name);
    kprobe_target_obj = bpf_object__open(target_path);
    if (libbpf_get_error(kprobe_target_obj) || bpf_object__load(kprobe_target_obj)) {
        fprintf(stderr, "[wrapper] failed to load kprobe target\n");
        return -1;
    }

    // Wire tail call
    struct bpf_program *target_prog = bpf_object__find_program_by_name(kprobe_target_obj, target_name);
    if (!target_prog) {
        fprintf(stderr, "[wrapper] kprobe target program not found\n");
        return -1;
    }

    struct bpf_map *prog_array = bpf_object__find_map_by_name(kprobe_wrapper_obj, "prog_array");
    if (!prog_array) {
        fprintf(stderr, "[wrapper] prog_array not found\n");
        return -1;
    }

    __u32 key = 2;  // KPROBE_PROG_INDEX
    int target_fd = bpf_program__fd(target_prog);
    if (bpf_map_update_elem(bpf_map__fd(prog_array), &key, &target_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[wrapper] failed to wire kprobe tail call\n");
        return -1;
    }

    printf("[wrapper] kprobe tail call wired: wrapper -> %s\n", target_name);
    return 0;
}

// Load sockops wrapper, wire to target
static int load_sockops_wrapper(const char *target_name)
{
    char wrapper_path[512], target_path[512];
    snprintf(wrapper_path, sizeof(wrapper_path), ".output/sockops_wrapper.o");
    snprintf(target_path, sizeof(target_path), ".output/%s.o", target_name);

    if (access(wrapper_path, F_OK) != 0 || access(target_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] sockops wrapper or target missing\n");
        return -1;
    }

    // Load wrapper
    printf("[wrapper] loading sockops wrapper\n");
    sockops_wrapper_obj = bpf_object__open(wrapper_path);
    if (libbpf_get_error(sockops_wrapper_obj) || bpf_object__load(sockops_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to load sockops wrapper\n");
        return -1;
    }

    // Note: Sockops attachment requires cgroup path
    // Skipping attachment for now

    ensure_shared_maps_pinned(sockops_wrapper_obj);

    // Load target
    printf("[wrapper] loading sockops target %s\n", target_name);
    sockops_target_obj = bpf_object__open(target_path);
    if (libbpf_get_error(sockops_target_obj) || bpf_object__load(sockops_target_obj)) {
        fprintf(stderr, "[wrapper] failed to load sockops target\n");
        return -1;
    }

    // Wire tail call
    struct bpf_program *target_prog = bpf_object__find_program_by_name(sockops_target_obj, target_name);
    if (!target_prog) {
        fprintf(stderr, "[wrapper] sockops target program not found\n");
        return -1;
    }

    struct bpf_map *prog_array = bpf_object__find_map_by_name(sockops_wrapper_obj, "prog_array");
    if (!prog_array) {
        fprintf(stderr, "[wrapper] prog_array not found\n");
        return -1;
    }

    __u32 key = 3;  // SOCKOPS_PROG_INDEX
    int target_fd = bpf_program__fd(target_prog);
    if (bpf_map_update_elem(bpf_map__fd(prog_array), &key, &target_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[wrapper] failed to wire sockops tail call\n");
        return -1;
    }

    printf("[wrapper] sockops tail call wired: wrapper -> %s\n", target_name);
    return 0;
}

// Load fentry wrapper, wire to target
static int load_fentry_wrapper(const char *target_name)
{
    char wrapper_path[512], target_path[512];
    snprintf(wrapper_path, sizeof(wrapper_path), ".output/fentry_wrapper.o");
    snprintf(target_path, sizeof(target_path), ".output/%s.o", target_name);

    if (access(wrapper_path, F_OK) != 0 || access(target_path, F_OK) != 0) {
        fprintf(stderr, "[wrapper] fentry wrapper or target missing\n");
        return -1;
    }

    // Load wrapper
    printf("[wrapper] loading fentry wrapper\n");
    fentry_wrapper_obj = bpf_object__open(wrapper_path);
    if (libbpf_get_error(fentry_wrapper_obj) || bpf_object__load(fentry_wrapper_obj)) {
        fprintf(stderr, "[wrapper] failed to load fentry wrapper\n");
        return -1;
    }

    // Note: Fentry attachment requires BTF and specific function
    // Skipping attachment for now

    ensure_shared_maps_pinned(fentry_wrapper_obj);

    // Load target
    printf("[wrapper] loading fentry target %s\n", target_name);
    fentry_target_obj = bpf_object__open(target_path);
    if (libbpf_get_error(fentry_target_obj) || bpf_object__load(fentry_target_obj)) {
        fprintf(stderr, "[wrapper] failed to load fentry target\n");
        return -1;
    }

    // Wire tail call
    struct bpf_program *target_prog = bpf_object__find_program_by_name(fentry_target_obj, target_name);
    if (!target_prog) {
        fprintf(stderr, "[wrapper] fentry target program not found\n");
        return -1;
    }

    struct bpf_map *prog_array = bpf_object__find_map_by_name(fentry_wrapper_obj, "prog_array");
    if (!prog_array) {
        fprintf(stderr, "[wrapper] prog_array not found\n");
        return -1;
    }

    __u32 key = 4;  // FENTRY_PROG_INDEX
    int target_fd = bpf_program__fd(target_prog);
    if (bpf_map_update_elem(bpf_map__fd(prog_array), &key, &target_fd, BPF_ANY) != 0) {
        fprintf(stderr, "[wrapper] failed to wire fentry tail call\n");
        return -1;
    }

    printf("[wrapper] fentry tail call wired: wrapper -> %s\n", target_name);
    return 0;
}

int main(int argc, char **argv)
{
    const char *ifname = "lima0";
    const char *config_path = "../configs/config.json";

    if (argc > 1) {
        ifname = argv[1];
    }
    if (argc > 2) {
        config_path = argv[2];
    }

    printf("[wrapper] Wrapper Loader starting. Interface=%s Config=%s\n", ifname, config_path);

    FILE *fp = fopen(config_path, "rb");
    if (!fp) {
        fprintf(stderr, "[wrapper] cannot open %s\n", config_path);
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(fsz + 1);
    if (!buf || fread(buf, 1, fsz, fp) != (size_t)fsz) {
        fclose(fp);
        free(buf);
        fprintf(stderr, "[wrapper] read failed\n");
        return 1;
    }
    buf[fsz] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        fprintf(stderr, "[wrapper] JSON parse failed\n");
        return 1;
    }

    // Check if wrappers enabled
    cJSON *use_wrappers_json = cJSON_GetObjectItemCaseSensitive(root, "use_wrappers");
    int use_wrappers = (use_wrappers_json && cJSON_IsBool(use_wrappers_json) && cJSON_IsTrue(use_wrappers_json));
    
    if (!use_wrappers) {
        printf("[wrapper] Wrappers disabled in config, exiting\n");
        cJSON_Delete(root);
        return 0;
    }

    printf("[wrapper] Wrappers ENABLED\n");

    cJSON *targets = cJSON_GetObjectItemCaseSensitive(root, "targets");
    if (!targets || !cJSON_IsArray(targets)) {
        fprintf(stderr, "[wrapper] 'targets' missing\n");
        cJSON_Delete(root);
        return 1;
    }

    int n = cJSON_GetArraySize(targets);
    int xdp_loaded = 0, tc_loaded = 0, kprobe_loaded = 0, sockops_loaded = 0, fentry_loaded = 0;

    // Load wrappers for each target type
    for (int i = 0; i < n; i++) {
        cJSON *t = cJSON_GetArrayItem(targets, i);
        if (!t || !cJSON_IsObject(t)) continue;

        cJSON *jname = cJSON_GetObjectItemCaseSensitive(t, "name");
        cJSON *jtype = cJSON_GetObjectItemCaseSensitive(t, "type");
        
        if (!jname || !cJSON_IsString(jname)) continue;
        if (!jtype || !cJSON_IsString(jtype)) continue;

        const char *name = jname->valuestring;
        const char *type = jtype->valuestring;

        if (strcmp(type, "xdp") == 0 && !xdp_loaded) {
            if (load_xdp_wrapper(ifname, name) == 0) {
                xdp_loaded = 1;
            }
        } else if (strcmp(type, "tc") == 0 && !tc_loaded) {
            if (load_tc_wrapper(ifname, name) == 0) {
                tc_loaded = 1;
            }
        } else if (strcmp(type, "kprobe") == 0 && !kprobe_loaded) {
            if (load_kprobe_wrapper(name) == 0) {
                kprobe_loaded = 1;
            }
        } else if (strcmp(type, "sockops") == 0 && !sockops_loaded) {
            if (load_sockops_wrapper(name) == 0) {
                sockops_loaded = 1;
            }
        } else if (strcmp(type, "fentry") == 0 && !fentry_loaded) {
            if (load_fentry_wrapper(name) == 0) {
                fentry_loaded = 1;
            }
        }
    }

    cJSON_Delete(root);
    
    int total_loaded = xdp_loaded + tc_loaded + kprobe_loaded + sockops_loaded + fentry_loaded;
    if (total_loaded > 0) {
        printf("[wrapper] Loaded %d wrapper(s): XDP=%d TC=%d kprobe=%d sockops=%d fentry=%d\n",
               total_loaded, xdp_loaded, tc_loaded, kprobe_loaded, sockops_loaded, fentry_loaded);
        printf("[wrapper] NOTE: Keep this process running or objects will be unloaded\n");
        printf("[wrapper] Press Ctrl+C when done\n");
        pause(); // Keep process alive
    } else {
        printf("[wrapper] No wrappers loaded\n");
    }

    return 0;
}
