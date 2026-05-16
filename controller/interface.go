//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	"golang.org/x/sys/unix"
)

// InterfaceManager 维护已挂载网卡的状态
type InterfaceManager struct {
	mounted sync.Map // map[string]*bpfObjects (存储加载的对象以便后续关闭)

	// 传入加载好的 eBPF 模块程序的文件描述符（FD）或对象
	ingressProgFd int
	egressProgFd  int
}

func NewInterfaceManager(ingressFd, egressFd int) *InterfaceManager {
	return &InterfaceManager{
		ingressProgFd: ingressFd,
		egressProgFd:  egressFd,
	}
}

// Watch 独立线程：动态监听网卡变化
func (m *InterfaceManager) Watch(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	log.Println("Interface Watcher started (Native Netlink/eBPF enabled)")

	for {
		m.scanAndAttach()
		select {
		case <-ctx.Done():
			log.Println("Interface Watcher stopping, cleaning up...")
			m.CleanupAll()
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
		// 过滤逻辑：忽略本地环回或未启动的网卡
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// 如果该网卡未被记录
		if _, loaded := m.mounted.Load(iface.Name); !loaded {
			// 传入网卡的 Index 和 Name
			if err := m.attachNative(iface.Index, iface.Name); err == nil {
				m.mounted.Store(iface.Name, true)
				log.Printf("[eBPF] 成功挂载新网卡: %s (Index: %d)", iface.Name, iface.Index)
			} else {
				log.Printf("[eBPF] 挂载至网卡 %s 失败: %v", iface.Name, err)
			}
		}
	}
}

// attachNative
func (m *InterfaceManager) attachNative(ifIndex int, ifName string) error {
	// 构造 clsact qdisc 属性
	attrs := netlink.QdiscAttrs{
		LinkIndex: ifIndex,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	// 尝试添加 clsact (如果已存在则先删除再添加)
	if err := netlink.QdiscAdd(qdisc); err != nil {
		if os.IsExist(err) {
			_ = netlink.QdiscDel(qdisc)
			err = netlink.QdiscAdd(qdisc)
		}
		if err != nil {
			return fmt.Errorf("cannot add clsact qdisc: %w", err)
		}
	}

	// 挂载 Ingress 过滤器
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: ifIndex,
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_IP,
		Priority:  1, // 优先级
	}

	ingressFilter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           m.ingressProgFd, // 纯 Go 直接传递内核中的 eBPF 程序句柄
		Name:         "clash-ingress-" + ifName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		_ = netlink.QdiscDel(qdisc) // 失败时回滚
		return fmt.Errorf("cannot attach ebpf to ingress: %w", err)
	}

	// 挂载 Egress 过滤器
	filterAttrsEgress := netlink.FilterAttrs{
		LinkIndex: ifIndex,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_IP,
		Priority:  1,
	}

	egressFilter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrsEgress,
		Fd:           m.egressProgFd, // 纯 Go 直接传递内核中的 eBPF 程序句柄
		Name:         "clash-egress-" + ifName,
		DirectAction: true,
	}

	if err := netlink.FilterAdd(egressFilter); err != nil {
		_ = netlink.FilterDel(ingressFilter)
		_ = netlink.QdiscDel(qdisc)
		return fmt.Errorf("cannot attach ebpf to egress: %w", err)
	}

	return nil
}

// CleanupAll 当程序退出时，干净利落地清理所有网卡上的驱动
func (m *InterfaceManager) CleanupAll() {
	m.mounted.Range(func(key, value interface{}) bool {
		ifName := key.(string)
		iface, err := net.InterfaceByName(ifName)
		if err == nil {
			attrs := netlink.QdiscAttrs{
				LinkIndex: iface.Index,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_CLSACT,
			}
			qdisc := &netlink.GenericQdisc{QdiscAttrs: attrs, QdiscType: "clsact"}
			_ = netlink.QdiscDel(qdisc)
			log.Printf("[eBPF] 已卸载网卡 %s 的驱动", ifName)
		}
		m.mounted.Delete(ifName)
		return true
	})
}
