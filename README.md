# eBPF Traffic Marker (流量标记系统)

这是一个基于 eBPF 技术实现的高性能流量标记系统。它能够通过 **DNS 报文嗅探 (PCAP)** 自动识别域名与 IP 的对应关系，在内核层级对网络报文（skb）进行 `skb->mark` 标记。

## 🌟 核心特性

- **全自动加载**: 基于 Go 实现的数据面驱动，启动即自动加载 eBPF 字节码并挂载至所有活动物理网卡。
- **智能域名识别**: 使用 `libpcap` 实时抓取并解析 DNS 响应报文，动态获取域名背后的 IP 地址池。
- **LPM 匹配机制**: 内核态采用 `LPM_TRIE` Map，支持精确 IP 或 CIDR 网段的高效匹配。
- **动态策略下发**: 监控面发现 IP 变动后，自动更新内核 Map，无需重启服务或重载配置。
- **多网卡适配**: 自动扫描系统 UP 状态的物理网卡，同步挂载 Ingress 与 Egress 钩子。

## 🏗️ 系统架构
系统由数据面与控制面解耦设计，通过 BPF文件系统 (bpffs) 共享状态：
系统分为两个主要部分：
1.  **数据面 (Dataplane)**:
    *   **内核态 (C)**: 挂载在 TC 钩子，执行报文解析与 LPM_TRIE 查表标记。
    *   **用户态 (C++/Go)**: 负责 eBPF 程序的加载、多网卡挂载及 Map 持久化。
2.  **控制面 (Control Plane)**:
    *   **Go**: 负责 DNS 流量嗅探、业务逻辑处理、IP 变动监控及 Map 策略下发。

## 📂 目录结构
```text
├── controller/              # 数据面（加载/管理）和控制面（逻辑/下发 (Go代码)
│   ├── config.go             # 静态策略配置 (域名与 Mark 对应关系)
│   ├── engine.go.           # Go 控制面核心逻辑
│   ├── main.go              # Go 项目入口
│   ├── traffic_mark.bpf.c    # eBPF 内核逻辑 (与数据面共享)
│   └── watcher.go           # 域名/IP 变化监控
├── dataplane-cpp/              # 数据面 (eBPF 内核代码与加载器)
│   ├── traffic_mark.bpf.c   # eBPF 内核逻辑
│   ├── loader.cpp          # C++ 加载器程序
│   ├── Makefile             # 编译与环境预检工具
│   └── traffic_mark.skel.h  # 自动生成的 BPF 骨架 (编译后生成)
├── engine.go             # Go 控制面核心逻辑
├── watcher.go            # 域名/IP 变化监控
├── main.go               # Go 项目入口
├── config.go             # 静态策略配置 (域名与 Mark 对应关系)
└── README.md             # 项目文档
```

## 🛠️ 环境要求
1. 运行环境:
- OS: Linux Kernel >= 5.10 (推荐 5.15+)
- 工具链: clang, llvm, libbpf-dev, make, g++
- Go: 1.18 或更高版本
- 权限: 运行加载器和 Go 引擎需要 root 权限

2. 依赖库:
```Bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y clang llvm libbpf-dev libpcap-dev make g++

```

## 🚀 快速开始
### 选项 A：仅使用 Golang 实现 (推荐)
适用于需要高度集成、一键启动的场景。
```Bash
# 进入目录
cd controller
# 1. 下载依赖
go mod tidy
# 2. 编译并运行
go generate # 生成 BPF 骨架文件
go build -o traffic_marker .
sudo ./traffic_marker
```

### 选项 B：C++ 数据面 + Go 控制面
数据面必须先启动，因为它负责创建并固定（Pin）共享的 BPF Map 路径。
- 启动数据面加载器：
```Bash
cd dataplane
# 1. 自动编译 BPF 字节码并生成加载器
make clean && make

# 2. 启动加载器 (会自动处理 BPF FS 挂载与网卡挂载)
sudo ./loader
```
注意: 请保持该终端窗口开启。加载器在退出时会自动清理网卡上的 eBPF 钩子。

- 运行控制面 (Go)
另开一个终端窗口，启动 Go 引擎：
```Bash
# 1. 下载依赖
go mod tidy

# 2. 编译并运行 (需要 root 权限以加载 BPF 程序和开启 PCAP 监听)
go build -o control_plane .
sudo ./control_plane
```

### 配置说明
在 config.go 或配置文件中定义域名与 Mark 的关系：
- google.com -> 0x64 (100)
- github.com -> 0xC8 (200)
- baidu.com  -> 0x12C (300)

## ⚙️ 技术原理
1. DNS 嗅探: Agent 通过 gopacket/pcap 监听 53 端口的 UDP 报文。
2. 关联分析: 当检测到 DNS 响应（Answer）时，提取 A 记录中的 IP 地址。
3. Map 更新: Agent 调用 cilium/ebpf 库，将 IP -> Mark 写入内核中的 LPM_TRIE Map。
4. 内核标记: 挂载在 TC (Traffic Control) 钩子上的 eBPF 程序对通过的报文进行查找，若匹配则执行 skb->mark = value

## 🧹 卸载与清理
当需要停止系统时，首先关闭 Go 引擎，然后在数据面终端按 Ctrl+C 退出加载器。加载器会自动清理所有挂载的 eBPF 钩子和 Map。
1. 自动从所有网卡移除 TC 过滤器。
2. 销毁 clsact 队列。
3. 删除 /sys/fs/bpf/ip_marks 路径。

```Bash
sudo tc qdisc del dev <你的网卡名> clsact
sudo rm /sys/fs/bpf/ip_marks
```

## 🔍 关键技术实现
- LPM Trie Map: 使用 BPF_MAP_TYPE_LPM_TRIE 存储 IP 段规则，支持高效的长前缀匹配（CIDR），可处理单个 IP 或网段。
- Map 共享: 依靠 bpffs (BPF 文件系统) 将 Map 固定在 /sys/fs/bpf/ip_marks，实现 C++ 与 Go 的跨进程通信。
- Libraries: 使用 cilium/ebpf 进行 Go 端的 eBPF 程序加载与 Map 操作，使用 google/gopacket (pcap) 实现 DNS 报文的实时嗅探与解析。使用 libbpf-dev 在 C++ 端编译和加载 eBPF 程序。
- 多网卡适配: 通过 net.Interfaces() 动态获取物理接口，支持多网卡环境下的统一标记。