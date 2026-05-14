package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

type ipKey struct {
	Prefixlen uint32
	Ipv4Addr  uint32
}

type Record struct {
	Mark uint32
	End  time.Time
}

type Engine struct {
	bpfMap *ebpf.Map
	cache  sync.Map
	// 策略读写锁：支持运行时热更新
	lock  sync.RWMutex
	rules map[string]uint32
}

func NewEngine(m *ebpf.Map, rules map[string]uint32) *Engine {
	return &Engine{bpfMap: m, rules: rules}
}

func (e *Engine) Reload(rules map[string]uint32) {
	e.lock.Lock()
	defer e.lock.Unlock()
	e.rules = rules
	log.Printf("成功加载 %d 条新策略", len(rules))
}

// AddMapping 收到 DNS 后更新
func (e *Engine) AddMapping(domain string, ip net.IP, ttl uint32) {
	e.lock.RLock()
	var mark uint32
	var exists bool
	for ruleDomain, m := range e.rules {
		if domain == ruleDomain || (len(domain) > len(ruleDomain) && domain[len(domain)-len(ruleDomain)-1] == '.' && domain[len(domain)-len(ruleDomain):] == ruleDomain) {
			mark = m
			exists = true
			break
		}
	}
	e.lock.RUnlock()
	ipv4 := ip.To4()
	if !exists || ipv4 == nil {
		return
	}

	ipUint := binary.BigEndian.Uint32(ipv4)
	expire := time.Now().Add(time.Duration(ttl) * time.Second)

	e.cache.Store(ipUint, Record{mark, expire})

	e.syncToKernel(ipUint, mark, false)
	log.Printf("写入内核成功: %s (%d) -> Mark: %d", domain, ipUint, mark)
}

func (e *Engine) syncToKernel(ip uint32, mark uint32, remove bool) {
	if e == nil || e.bpfMap == nil {
		return
	}
	key := ipKey{
		Prefixlen: 32,
		Ipv4Addr:  ip,
	}

	var err error
	if remove {
		err = e.bpfMap.Delete(key)
	} else {
		err = e.bpfMap.Put(key, mark)
	}
	if err != nil {
		log.Printf("BPF Map 操作失败 (remove=%v): %v", remove, err)
	}
}

// Clean 定时清理过期 IP
func (e *Engine) Clean(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			e.cache.Range(func(k, v any) bool {
				ip, ok := k.(uint32)
				if !ok {
					return true
				}
				rec := v.(Record)
				if now.After(rec.End) {
					e.syncToKernel(ip, 0, true)
					e.cache.Delete(ip)
				}
				return true
			})
		}
	}
}
