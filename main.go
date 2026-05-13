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
		o.IpMarks.Close()
	}
	if o.DoMark != nil {
		o.DoMark.Close()
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

	engine := NewEngine(objs.IpMarks, loadRules())
	if engine == nil {
		log.Fatal("...")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   objs.DoMark,
			Attach:    ebpf.AttachTCXEgress,
		})
		if err != nil {
			log.Printf("跳过网卡 %s: %v", iface.Name, err)
			continue
		}
		defer l.Close()
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
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)

	go func() {
		for range sigChan {
			log.Println("收到 SIGHUP，重新加载域名列表...")
			newRules := loadRules()
			engine.Reload(newRules)
		}
	}()

	// 退出
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)

	go engine.Clean(ctx)
	go WatchDNS(ctx, func(domain string, ip net.IP, ttl uint32) {
		if engine != nil {
			engine.AddMapping(domain, ip, ttl)
		}
	})

	log.Println("已启动， 输入 'kill -HUP <pid>' 触发配置重载。")
	log.Println("Traffic Engine is running. Press Ctrl+C to exit.")
	<-exit
}
