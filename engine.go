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

type ipKeyRaw [8]byte

/*
type ipKey struct {
	Prefixlen uint32
	Ipv4Addr  uint32
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

func (e *Engine) getMark(domain string) (uint32, bool) {
	e.lock.RLock()
	defer e.lock.RUnlock()

	// 完全匹配
	if m, ok := e.rules[domain]; ok {
		return m, true
	}

	// 后缀匹配 (如: sub.example.com 匹配 example.com)
	for ruleDomain, m := range e.rules {
		if len(domain) > len(ruleDomain) &&
			domain[len(domain)-len(ruleDomain)-1] == '.' &&
			domain[len(domain)-len(ruleDomain):] == ruleDomain {
			return m, true
		}
	}
	return 0, false
}

// AddMapping 收到 DNS 后更新
func (e *Engine) AddMapping(domain string, ip net.IP, ttl uint32) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return
	}
	mark, ok := e.getMark(domain)
	if !ok {
		return
	}

	var addr [4]byte
	copy(addr[:], ipv4)
	if ttl < 10 {
		ttl = 20
	}
	expire := time.Now().Add(time.Duration(ttl) * time.Second)

	// 更新缓存
	e.cache.Store(addr, Record{mark, expire})

	e.syncToKernel(addr, mark, false)
	log.Printf("写入内核成功: %s (%d) -> Mark: %d", domain, ipv4, mark)
}

func (e *Engine) syncToKernel(ip [4]byte, mark uint32, remove bool) {
	if e == nil || e.bpfMap == nil {
		return
	}
	var key ipKeyRaw
	binary.LittleEndian.PutUint32(key[0:4], 32)
	// key := ipKey{
	// 	Prefixlen: 32,
	// 	Ipv4Addr:  ip,
	// }
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
	ticker := time.NewTicker(15 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			count := 0
			e.cache.Range(func(k, v any) bool {
				ip, ok := k.([4]byte)
				if !ok {
					return true
				}
				rec := v.(Record)
				if now.After(rec.End) {
					log.Printf("【清理触发】域名过期，正在从内核删除 IP: %v", ip)
					e.syncToKernel(ip, 0, true)
					e.cache.Delete(ip)
					count++
				}
				return true
			})
			if count > 0 {
				log.Printf("[Cleanup] 已从内核清除 %d 条过期记录", count)
			}
		}
	}
}
