// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

// XDP program that prints packet length and accepts all packets
SEC("xdp")
int xdp_handler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // __u32 pkt_len = data_end - data;
    
    // // Print packet length
    // bpf_printk("[XDP] Packet received, length: %u bytes\n", pkt_len);
    
    // Accept all packets
    return XDP_PASS;
}
