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
	Addr      uint32
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
	mark, exists := e.rules[domain]
	e.lock.RUnlock()

	if !exists || ip.To4() == nil {
		return
	}

	ipv4 := binary.BigEndian.Uint32(ip.To4())
	expire := time.Now().Add(time.Duration(ttl) * time.Second)

	e.cache.Store(ipv4, Record{mark, expire})

	e.syncToKernel(ipv4, mark, false)
}

func (e *Engine) syncToKernel(ip uint32, mark uint32, remove bool) {
	if e == nil || e.bpfMap == nil {
		return
	}

	key := ipKey{
		Prefixlen: 32,
		Addr:      ip,
	}

	if remove {
		_ = e.bpfMap.Delete(key)
	} else {
		_ = e.bpfMap.Put(key, mark)
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
