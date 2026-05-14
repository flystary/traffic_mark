package main

import (
	"context"
	"log"
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)
type ipKeyRaw [8]byte
/*
type ipKey struct {
	Prefixlen uint32
	Ipv4Addr  [4]byte
}
*/

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

	var addr [4]byte
	copy(addr[:], ipv4)
	expire := time.Now().Add(time.Duration(ttl) * time.Second)

	e.cache.Store(addr, Record{mark, expire})

	e.syncToKernel(addr, mark, false)
	log.Printf("写入内核成功: %s (%d) -> Mark: %d", domain, addr[:], mark)
}

func (e *Engine) syncToKernel(ip [4]byte, mark uint32, remove bool) {
	if e == nil || e.bpfMap == nil {
		return
	}
	var key ipKeyRaw
	/*
	key := ipKey{
		Prefixlen: 32,
		Ipv4Addr:  ip,
	}
        */
	binary.LittleEndian.PutUint32(key[0:4], 32)
	copy(key[4:8], ip[:])
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
			        ip, ok := k.([4]byte)
				if !ok { return true}
				rec := v.(Record)
				if now.After(rec.End) {
					e.syncToKernel(ip, 0, true)
					e.cache.Delete(k)
				}
				return true
			})
		}
	}
}
