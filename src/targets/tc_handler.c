// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tc")
int tc_handler(struct __sk_buff *skb)
{
    if (!skb)
        return TC_ACT_SHOT;

    __u32 pkt_len = skb->len;

    // bpf_printk("[TC] Packet received, length: %u bytes\n", pkt_len);

    /* Let the packet continue through the stack */
    return TC_ACT_OK;
}
