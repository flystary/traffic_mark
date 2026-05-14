#include <iostream>
#include <vector>
#include <string>
#include <csignal>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/resource.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "traffic_mark.skel.h"

// 存储已挂载的网卡索引，用于退出时清理
std::vector<int> attached_ifaces;
struct traffic_mark_bpf *skel = nullptr;
const char *BPF_MAP_PATH = "/sys/fs/bpf/ip_marks";

// 自定义一个空的日志处理器
int silent_libbpf_print(enum libbpf_print_level level, const char *format, va_list args)
{
    return 0;
}

// 清理函数 确保内核状态恢复原状
void cleanup(int sig)
{
    std::cout << "\n开始清理中..." << std::endl;

    for (int ifindex : attached_ifaces)
    {
        DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
                            .ifindex = ifindex,
                            .attach_point = (enum bpf_tc_attach_point)(BPF_TC_INGRESS | BPF_TC_EGRESS));
        // 销毁 clsact 会自动移除关联的所有 BPF 过滤器
        bpf_tc_hook_destroy(&hook);
    }

    if (skel)
    {
        traffic_mark_bpf__destroy(skel);
    }

    unlink(BPF_MAP_PATH);
    std::cout << "清理完成，退出程序。" << std::endl;
    exit(0);
}

bool attach_tc_clean(int ifindex, const char *ifname)
{
    // 定义 Hook 容器
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
                        .ifindex = ifindex,
                        .attach_point = (enum bpf_tc_attach_point)(BPF_TC_INGRESS | BPF_TC_EGRESS));
    // 屏蔽 "Invalid handle" 警告
    libbpf_print_fn_t old_print_fn = libbpf_set_print(silent_libbpf_print);
    // 先尝试删除可能存在的旧钩子（不检查返回值，因为可能不存在）
    bpf_tc_hook_destroy(&hook);

    // 恢复原来的日志处理器，以便后续真正的错误能被看见
    libbpf_set_print(old_print_fn);

    // 创建新的 clsact
    int err = bpf_tc_hook_create(&hook);
    if (err)
    {
        std::cerr << "[-] 无法为 " << ifname << " 创建 Hook: " << err << std::endl;
        return false;
    }

    // 挂载 Egress
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, egress_opts, .prog_fd = bpf_program__fd(skel->progs.do_mark_egress));
    hook.attach_point = BPF_TC_EGRESS;
    if (bpf_tc_attach(&hook, &egress_opts))
    {
        std::cerr << "[-] Egress 挂载失败: " << ifname << std::endl;
        return false;
    }

    // 挂载 Ingress
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ingress_opts, .prog_fd = bpf_program__fd(skel->progs.do_mark_ingress));
    hook.attach_point = BPF_TC_INGRESS;
    if (bpf_tc_attach(&hook, &ingress_opts))
    {
        std::cerr << "[-] Ingress 挂载失败: " << ifname << std::endl;
        return false;
    }

    std::cout << "[+] 成功重置并挂载 -> " << ifname << std::endl;
    attached_ifaces.push_back(ifindex);
    return true;
}

int main()
{
    // 1. 设置资源限制
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);

    // 2. 捕获退出信号
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // 3. 加载 BPF 骨架
    skel = traffic_mark_bpf__open_and_load();
    if (!skel)
    {
        std::cerr << "[-] 加载 BPF 失败" << std::endl;
        return 1;
    }

    // 4. Pin Map (Go 进程通过此路径更新 IP)
    unlink(BPF_MAP_PATH);
    int pin_err = bpf_map__pin(skel->maps.ip_marks, BPF_MAP_PATH);
    if (pin_err)
    {
        // 使用 strerror 打印具体原因，比如 "Permission denied" 或 "Busy"
        fprintf(stderr, "[-] Map 固定失败: %s (错误码: %d)\n", strerror(-pin_err), pin_err);
        cleanup(0);
    }
    else
    {
        printf("[+] Map 成功固定到: %s\n", BPF_MAP_PATH);
    }

    // 5. 遍历网卡进行挂载
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        return 1;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        /* 1. 接口没有地址信息
         * 2. 检查 Flags：必须是启动状态 (UP)，且不能是回环 (LOOPBACK)
         * 3. 是 127.0.0.1，跳过
         * 4. 同一个网卡的不同 IP 地址重复执行挂载逻辑
         */
        if (!ifa->ifa_addr || !(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK) || ifa->ifa_addr->sa_family != AF_PACKET)
            continue;

        std::string name = ifa->ifa_name;
        // 过滤不需要的接口
        if (name == "lo" || name.find("docker") != std::string::npos || name.find("veth") != std::string::npos)
        {
            continue;
        }

        if (!(ifa->ifa_flags & IFF_UP))
            continue;

        int ifindex = if_nametoindex(ifa->ifa_name);
        attach_tc_clean(ifindex, ifa->ifa_name);
    }
    freeifaddrs(ifaddr);

    std::cout << "\n[!] 已启动，Map 位于: " << BPF_MAP_PATH << std::endl;
    std::cout << "[!] 按 Ctrl+C 停止并自动清理环境..." << std::endl;

    while (true)
        pause();

    return 0;
}