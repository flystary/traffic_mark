//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct ip_key
{
    __u32 prefixlen;
    __u32 ipv4_addr;
} __attribute__((packed));

// LPM trie: prefix + ip
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65535);
    __type(key, struct ip_key);
    __type(value, __u32); // Mark
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_marks SEC(".maps");

SEC("classifier/egress")
int do_mark(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u32 dst = bpf_ntohl(iph->daddr);
    struct ip_key key = {
        .prefixlen = 32,
        .ipv4_addr = dst};

    // 匹配领域实体 IP
    __u32 *mark = bpf_map_lookup_elem(&ip_marks, &key);
    if (mark)
    {
        skb->mark = *mark;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";