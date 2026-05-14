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
	"github.com/cilium/ebpf/rlimit"
)

type TrafficObjects struct {
	// 对应 C 中的 ip_marks
	IpMarks *ebpf.Map `ebpf:"ip_marks"`
	// 对应 C 中的 SEC("classifier/egress") do_mark_egress
	DoMarkEgress *ebpf.Program `ebpf:"do_mark_egress"`
	// 对应 C 中的 SEC("classifier/egress") do_mark_ingress
	DoMarkIngress *ebpf.Program `ebpf:"do_mark_ingress"`
}

func (o *TrafficObjects) Close() error {
	if o.IpMarks != nil {
		_ = o.IpMarks.Close()
	}
	if o.DoMarkEgress != nil {
		_ = o.DoMarkEgress.Close()
	}
	if o.DoMarkIngress != nil {
		_ = o.DoMarkIngress.Close()
	}
	return nil
}

func loadRules() map[string]uint32 {
	return map[string]uint32{
		"google.com": 100,
		"github.com": 200,
		"baidu.com":  300,
		"shifen.com": 300,
	}
}

const bpfFSPath = "/sys/fs/bpf"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("无法解除内存限制: %v", err)
	}
	// 先获取 Spec（这是配置蓝图），而不是直接 Load
	spec, err := LoadTrafficMark()
	if err != nil {
		log.Fatalf("无法加载 TrafficMark Spec: %v", err)
	}

	// 在真正加载到内核前，修改 Map 的 Pinning 策略
	if m, ok := spec.Maps["ip_marks"]; ok {
		m.Pinning = ebpf.PinByName
	} else {
		log.Fatal("在 Spec 中找不到 ip_marks Map")
	}

	var objs TrafficObjects
	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// 它告诉 ebpf 库：如果 Map 设置了 PinByName，请把它放在这个目录下
			PinPath: bpfFSPath,
		},
	}

	// 加载 eBPF
	if err := LoadTrafficMarkObjects(&objs, &opts); err != nil {
		log.Fatalf("加载 eBPF 对象失败: %v", err)
	}
	defer objs.Close()
	os.Remove(bpfFSPath + "/prog_egress")
	os.Remove(bpfFSPath + "/prog_ingress")
	os.Remove(bpfFSPath + "/ip_marks")

	if err := objs.DoMarkEgress.Pin(bpfFSPath + "/prog_egress"); err != nil {
		log.Fatalf("无法 Pin Egress 程序: %v", err)
	}
	if err := objs.DoMarkIngress.Pin(bpfFSPath + "/prog_ingress"); err != nil {
		log.Fatalf("无法 Pin Ingress 程序: %v", err)
	}

	log.Printf("Map 指针: %p, Program指针 Egress: %p, Ingress: %p,", objs.IpMarks, objs.DoMarkEgress, objs.DoMarkIngress)

	// Engine
	engine := NewEngine(objs.IpMarks, loadRules())
	if engine == nil {
		log.Fatal("engine init failed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ifaces, _ := net.Interfaces()

	for _, iface := range ifaces {

		if iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagUp == 0 {
			continue
		}

		_ = exec.Command("tc", "qdisc", "del", "dev", iface.Name, "clsact").Run()
		_ = exec.Command("tc", "qdisc", "add", "dev", iface.Name, "clsact").Run()

		// 挂载 Egress (出站)
		errEgress := exec.Command("tc", "filter", "replace", "dev", iface.Name,
			"egress", "bpf", "da", "pinned", bpfFSPath+"/prog_egress").Run()
		if errEgress != nil {
			log.Printf("Egress 挂载失败 %s: %v", iface.Name, errEgress)
		}
		// 挂载 Ingress (入站)
		errIngress := exec.Command("tc", "filter", "replace", "dev", iface.Name,
			"ingress", "bpf", "da", "pinned", bpfFSPath+"/prog_ingress").Run()
		if errIngress != nil {
			log.Printf("Ingress 挂载失败 %s: %v", iface.Name, errIngress)
		}

		if errEgress != nil && errIngress != nil {
			continue
		}

		log.Printf("已挂载: %s", iface.Name)
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
	cancel()

	log.Println("bye")
}
