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
    __u8 addr[4];
} __attribute__((packed));
// LPM trie: prefix + ip
struct
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65535);
    __type(key, struct ip_key);
    __type(value, __u32); // Mark
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ip_marks SEC(".maps");

SEC("classifier/egress")
int do_mark_egress(struct __sk_buff *skb)
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

    bpf_printk("Egress dstIP Access: %pI4", &iph->daddr);
    struct ip_key key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->daddr, 4);

    __u32 *mark = bpf_map_lookup_elem(&ip_marks, &key);
    if (mark)
    {
        skb->mark = *mark;
        bpf_printk("Match! daddr=%x, mark=%d\n",
                   bpf_ntohl(iph->daddr),
                   *mark);
    }

    return TC_ACT_OK;
}

// 新增的 Ingress 钩子
SEC("classifier/ingress")
int do_mark_ingress(struct __sk_buff *skb)
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

    // bpf_printk("Ingress srcIP Access: %pI4", &iph->daddr);
    struct ip_key key = {
        .prefixlen = 32,
    };
    __builtin_memcpy(key.addr, &iph->saddr, 4);

    __u32 *mark = bpf_map_lookup_elem(&ip_marks, &key);
    if (mark)
    {
        skb->mark = *mark;
        bpf_printk("Match! saddr=%x, mark=%d\n",
                   bpf_ntohl(iph->saddr),
                   *mark);
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
