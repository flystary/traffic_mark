package main

// 执行此指令会生成两组文件：trafficmark_bpfel.go (小端) 和 trafficmark_bpfeb.go (大端)
// "TrafficMark" 是生成结构体的前缀名
// "traffic_mark.bpf.c" 是源文件
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target arm64 -cflags "-I/usr/include/aarch64-linux-gnu" TrafficMark traffic_mark.bpf.c

import (
	"context"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type TrafficObjects struct {
	// 对应 C 中的 ip_marks
	IpMarks *ebpf.Map `ebpf:"ip_marks"`
	// 对应 C 中的 SEC("classifier/egress") do_mark
	DoMark *ebpf.Program `ebpf:"do_mark"`
}

func (o *TrafficObjects) Close() error {
	if o.IpMarks != nil {
		_ = o.IpMarks.Close()
	}
	if o.DoMark != nil {
		_ = o.DoMark.Close()
	}
	return nil
}

func loadRules() map[string]uint32 {
	return map[string]uint32{
		"google.com": 100,
		"github.com": 200,
		"baidu.com":  300,
	}
}

func attachWithTC(iface string) error {
	cmd := exec.Command(
		"tc", "filter", "add",
		"dev", iface,
		"egress",
		"bpf", "da",
		"obj", "traffic_mark.o",
		"sec", "classifier/egress",
	)
	return cmd.Run()
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("无法解除内存限制: %v", err)
	}

	// 加载 eBPF
	var objs TrafficObjects
	if err := LoadTrafficMarkObjects(&objs, nil); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()

	log.Printf("Map 指针: %p, Program 指针: %p", objs.IpMarks, objs.DoMark)

	// Engine
	engine := NewEngine(objs.IpMarks, loadRules())
	if engine == nil {
		log.Fatal("engine init failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ifaces, _ := net.Interfaces()
	var links []link.Link

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagUp == 0 {
			continue
		}
		attachWithTC(iface.Name)

		l, err := link.AttachRawLink(link.RawLinkOptions{
			Program: objs.DoMark,
			Attach:  ebpf.AttachType(3), // TC classifier
			Target:  iface.Index,
		})

		if err != nil {
			log.Printf("跳过网卡 %s: %v", iface.Name, err)
			continue
		}

		links = append(links, l)
		log.Printf("成功挂载网卡: %s", iface.Name)
		/*
			l, err := link.RawAttachProgram(link.RawAttachProgramOptions{
				Target:  iface.Index,
				Program: objs.MarkProg,
				Attach:  ebpf.AttachClassifierEgress,
			})
		*/
	}

	// 热加载
	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGHUP)

	go func() {
		for range sigReload {
			log.Println("SIGHUP: reload rules")
			engine.Reload(loadRules())
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
	for _, l := range links {
		_ = l.Close()
	}
	cancel()

	log.Println("bye")
}
