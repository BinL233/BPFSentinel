// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_handler_2(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // __u32 pkt_len = data_end - data;
    // bpf_printk("[XDP2] Packet received, length: %u bytes\n", pkt_len);

    if (data_end < data) {
        return XDP_ABORTED+1000;
    }

    return XDP_PASS+1000;
}
