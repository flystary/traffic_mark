package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
)

const bpfFSPath = "/sys/fs/bpf/ip_marks"

func main() {
	// 创建全局唯一的上下文，监听系统退出信号 (SIGINT, SIGTERM)
	// 当按下 Ctrl+C 或收到 kill 信号时，ctx.Done() 会关闭
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 加载 BPF 资源
	bpfMap, err := ebpf.LoadPinnedMap(bpfFSPath, nil)
	if err != nil {
		log.Fatalf("Fatal: BPF Map load failed: %v", err)
	}
	defer bpfMap.Close()

	// 初始化引擎
	engine := NewEngine(bpfMap, LoadRules())

	// 统一管理协程生命周期
	var wg sync.WaitGroup

	// 监听 SIGHUP (热重载)
	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGHUP)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-sigReload:
				log.Println("Reloading rules...")
				engine.Reload(LoadRules())
			case <-ctx.Done(): // 收到退出信号，结束热重载协程
				return
			}
		}
	}()

	// 启动清理任务
	wg.Add(1)
	go func() {
		defer wg.Done()
		engine.Clean(ctx)
	}()

	// 启动 DNS 监听
	wg.Add(1)
	go func() {
		defer wg.Done()
		WatchDNS(ctx, func(domain string, ip net.IP, ttl uint32) {
			engine.AddMapping(domain, ip, ttl)
		})
	}()

	log.Println("Traffic Engine is running. Press Ctrl+C to stop.")

	<-ctx.Done()

	log.Println("Shutting down... waiting for workers to finish.")

	wg.Wait()
	log.Println("Goodbye.")
}