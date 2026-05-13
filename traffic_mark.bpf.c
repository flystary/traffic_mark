//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_key
{
    __u32 prefix;
    __u32 ipv4_addr;
};

// 领域语义：存储已识别的实体 IP 及其对应的路由标记
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65535);
    __type(key, struct ip_key);
    __type(value, __u32); // 存储 PolicyMark
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_marks SEC(".maps");

SEC("classifier/egress")
int do_mark(struct __sk_buff *skb)
{
    if (skb->protocol != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    struct ip_key key = {
        .prefix = 32,
        .ipv4_addr = iph->daddr};

    // 匹配领域实体 IP
    __u32 *mark = bpf_map_lookup_elem(&ip_marks, &key);
    if (mark)
    {
        skb->mark = *mark;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";