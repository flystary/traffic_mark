package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
)

const bpfFSPath = "/sys/fs/bpf/ip_marks"

func main() {
	// 加载 eBPF
	bpfMap, err := ebpf.LoadPinnedMap(bpfFSPath, nil)
	if err != nil {
		log.Fatalf("找不到 BPF Map，请确认 C++ 加载器已运行: %v", err)
	}
	defer bpfMap.Close()

	// Engine
	engine := NewEngine(bpfMap, LoadRules())
	if engine == nil {
		log.Fatal("engine init failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 热加载
	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGHUP)

	go func() {
		for range sigReload {
			log.Println("SIGHUP: reload rules")
			engine.Reload(LoadRules())
		}
	}()

	// 退出
	sigExit := make(chan os.Signal, 1)
	signal.Notify(sigExit, syscall.SIGINT, syscall.SIGTERM)

	go engine.Clean(ctx)
	go WatchDNS(ctx, func(domain string, ip net.IP, ttl uint32) {
		if engine != nil {
			engine.AddMapping(domain, ip, ttl)
		}
	})
	log.Println("Traffic Engine started")
	<-sigExit

	log.Println("shutting down...")
	cancel()

	log.Println("bye")
}
