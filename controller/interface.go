package main

import (
	"context"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"
)

// InterfaceManager 维护已挂载网卡的状态，防止重复挂载
type InterfaceManager struct {
	mounted sync.Map // map[string]bool
	egress  string
	ingress string
}

func NewInterfaceManager(egress, ingress string) *InterfaceManager {
	return &InterfaceManager{
		egress:  egress,
		ingress: ingress,
	}
}

// Watch 独立线程：动态监听网卡变化
func (m *InterfaceManager) Watch(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second) // 每10秒扫描一次新网卡
	defer ticker.Stop()

	log.Println("Interface Watcher started (dynamic mounting enabled)")

	for {
		m.scanAndAttach()
		select {
		case <-ctx.Done():
			log.Println("Interface Watcher stopping...")
			return
		case <-ticker.C:
		}
	}
}

func (m *InterfaceManager) scanAndAttach() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Failed to list interfaces: %v", err)
		return
	}

	for _, iface := range ifaces {
		// 过滤逻辑
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 如果该网卡未被记录，或者尝试重新挂载
		if _, loaded := m.mounted.Load(iface.Name); !loaded {
			if err := m.attach(iface.Name); err == nil {
				m.mounted.Store(iface.Name, true)
				log.Printf("Successfully attached eBPF to new interface: %s", iface.Name)
			} else {
				log.Printf("Failed to attach to %s: %v", iface.Name, err)
			}
		}
	}
}

func (m *InterfaceManager) attach(name string) error {
	// 1. 尝试清理旧的 clsact
	_ = exec.Command("tc", "qdisc", "del", "dev", name, "clsact").Run()

	// 2. 添加新的 clsact
	if err := exec.Command("tc", "qdisc", "add", "dev", name, "clsact").Run(); err != nil {
		return err
	}

	// 3. 挂载 Egress
	if err := exec.Command("tc", "filter", "replace", "dev", name, "egress", "bpf", "da", "pinned", m.egress).Run(); err != nil {
		return err
	}

	// 4. 挂载 Ingress
	if err := exec.Command("tc", "filter", "replace", "dev", name, "ingress", "bpf", "da", "pinned", m.ingress).Run(); err != nil {
		return err
	}

	return nil
}
