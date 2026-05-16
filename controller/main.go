package main

// "traffic_mark.bpf.c" 是源文件
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cflags "-I/usr/include/aarch64-linux-gnu" TrafficMark traffic_mark.bpf.c

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bpfFSPath  = "/sys/fs/bpf"
	bpfMapName = "ip_marks"
)

// checkBPFFS 确保 BPF 文件系统已正确挂载
func checkBPFFS() error {
	if err := os.MkdirAll(bpfFSPath, 0700); err != nil {
		log.Fatalf("Failed to create bpf fs directory: %v", err)
		return err
	}
	err := syscall.Mount("bpf", bpfFSPath, "bpf", 0, "")
	if err != nil {
		// EBUSY，说明系统已经挂载过
		if errno, ok := err.(syscall.Errno); ok && errno == syscall.EBUSY {
			return nil
		}
		return err
	}
	return nil
}

func main() {
	// 解除内存锁限制（eBPF 必须）
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("无法解除内存限制: %v", err)
	}
	if err := checkBPFFS(); err != nil {
		log.Fatalf("初始化 BPF 文件系统失败 (请确保以 sudo 权限运行): %v", err)
	}
	// 信号与上下文管理
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 加载 eBPF 资源
	spec, err := LoadTrafficMark()
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	// 在真正加载到内核前，修改 Map 的 Pinning 策略
	if m, ok := spec.Maps["ip_marks"]; ok {
		m.Pinning = ebpf.PinByName
	}
	// 强制清理历史残留的 Map 文件
	residualMapPath := filepath.Join(bpfFSPath, bpfMapName)
	if _, err := os.Stat(residualMapPath); err == nil {
		log.Println("清理运行残留的旧 Map 文件")
		_ = os.Remove(residualMapPath)
	}

	var objs TrafficMarkObjects
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfFSPath},
	}

	// 加载 eBPF
	if err := LoadTrafficMarkObjects(&objs, &opts); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	// log.Printf("Map 指针: %p, Program指针 Egress: %p, Ingress: %p,", objs.IpMarks, objs.DoMarkEgress, objs.DoMarkIngress)

	// Engine
	// 加载域名规则映射（例如：*.google.com -> Mark 10）
	engine := NewEngine(objs.IpMarks, LoadRules())
	if engine == nil {
		log.Fatal("engine init failed")
	}

	// 初始化网卡挂载管理器
	ifaceMgr := NewInterfaceManager(objs.DoMarkIngress.FD(), objs.DoMarkEgress.FD())

	// 动态网卡监听与 TC 挂载
	go ifaceMgr.Watch(ctx)

	// 过期 IP 自动清理
	go engine.Clean(ctx)

	// DNS 流量审计与学习
	go WatchDNS(ctx, func(domain string, ip net.IP, ttl uint32) {
		// 当拦截到 DNS 响应时，Engine 会自动根据 rules 决定是否写入 BPF Map
		engine.AddMapping(domain, ip, ttl)
	})

	// 热加载
	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGHUP)

	go func() {
		for {
			select {
			case <-sigReload:
				log.Println("SIGHUP received, reloading rules...")
				engine.Reload(LoadRules())
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Println("Traffic Engine started")
	// 阻塞等待退出信号
	<-ctx.Done()

	log.Println("shutting down...")
	time.Sleep(800 * time.Millisecond)

	log.Println("bye")
}
