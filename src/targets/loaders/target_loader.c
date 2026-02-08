#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include "utils/cJSON.h"
#include "loader_common.h"

static enum { LOAD_NONE=0, LOAD_XDP, LOAD_TC, LOAD_KPROBE, LOAD_SOCKOPS, LOAD_FENTRY } decide_type(const char *name)
{
    if (!name) {
        return LOAD_NONE;
    }
    
    if (strstr(name, "xdp")) {
        return LOAD_XDP;
    }

    if (strstr(name, "tc")) {
        return LOAD_TC;
    }
    
    if (strstr(name, "kprobe")) {
        return LOAD_KPROBE;
    }

    if (strstr(name, "sockops")) {
        return LOAD_SOCKOPS;
    }
    
    if (strstr(name, "fentry")) {
        return LOAD_FENTRY;
    }
    
    return LOAD_NONE;
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

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "[target] interface %s not found\n", ifname);
        return 1;
    }

    printf("[target] Dispatcher starting. Interface=%s Config=%s\n", ifname, config_path);

    FILE *fp = fopen(config_path, "rb");

    if (!fp) {
        fprintf(stderr, "[target] warning: cannot open %s; attempting default xdp_handler only\n", config_path);
        load_xdp_program(ifname, "xdp_handler");
        printf("[target] done (fallback path).\n");
        return 0;
    }

    fseek(fp, 0, SEEK_END); long fsz = ftell(fp); fseek(fp, 0, SEEK_SET);
    char *buf = (char*)malloc((size_t)fsz + 1);

    if (!buf) { 
        fclose(fp); 
        fprintf(stderr, "[target] OOM\n"); 
        return 1; 
    }

    if (fread(buf, 1, (size_t)fsz, fp) != (size_t)fsz) {
        fclose(fp); 
        free(buf); 
        fprintf(stderr, "[target] read fail\n"); 
        return 1;
    }

    buf[fsz] = '\0'; fclose(fp);

    cJSON *root = cJSON_Parse(buf); free(buf);

    if (!root) { 
        fprintf(stderr, "[target] parse %s failed\n", config_path);
        return 1; 
    }

    cJSON *targets = cJSON_GetObjectItemCaseSensitive(root, "targets");

    if (!targets || !cJSON_IsArray(targets)) { 
        fprintf(stderr, "[target] 'targets' missing\n"); 
        cJSON_Delete(root); 
        return 1; 
    }

    int n = cJSON_GetArraySize(targets);
    printf("[target] found %d target(s)\n", n);

    int xdp_cnt=0, tc_cnt=0, kprobe_cnt=0, fentry_cnt=0, skipped=0;

    for (int i=0;i<n;i++) {
        cJSON *t = cJSON_GetArrayItem(targets, i);

        if (!t || !cJSON_IsObject(t)) {
            continue;
        }

        cJSON *jname = cJSON_GetObjectItemCaseSensitive(t, "name");

        if (!jname || !cJSON_IsString(jname)) {
            continue;
        }

        const char *name = jname->valuestring;
        int type = decide_type(name);

        switch (type) {
        case LOAD_XDP:
            xdp_cnt += (load_xdp_program(ifname, name) > 0);
            break;
        case LOAD_TC:
            tc_cnt += (load_tc_program(ifname, name) > 0);
            break;
        case LOAD_KPROBE:
            kprobe_cnt += (load_kprobe_program(ifname, name) > 0);
            break;
        case LOAD_SOCKOPS:
            kprobe_cnt += (load_sockops_program(ifname, name) > 0);
            break;
        case LOAD_FENTRY:
            fentry_cnt += (load_fentry_program(ifname, name) > 0);
            break;
        default:
            printf("[target] skipping '%s' (no loader implemented)\n", name);
            skipped++;
            break;
        }
    }

    cJSON_Delete(root);
    printf("[target] summary: XDP attached=%d TC attached=%d KPROBE attached=%d FENTRY attached=%d skipped=%d\n", xdp_cnt, tc_cnt, kprobe_cnt, fentry_cnt, skipped);
    return 0;
}
