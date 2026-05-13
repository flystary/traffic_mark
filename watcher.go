package main

import (
	"context"
	"log"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func WatchDNS(ctx context.Context, onDNS func(string, net.IP, uint32)) {
	if onDNS == nil {
		return
	}

	h, err := pcap.OpenLive("any", 1024, true, pcap.BlockForever)
	if err != nil {
		log.Printf("无法开启抓包: %v", err)
		return
	}
	defer h.Close()

	_ = h.SetBPFFilter("udp port 53 or tcp port 53")
	src := gopacket.NewPacketSource(h, h.LinkType())

	for {
		select {
		case <-ctx.Done():
			return

		case packet, ok := <-src.Packets():
			if !ok {
				return
			}

			// 安全解析 DNS 层
			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer == nil {
				continue
			}

			dns, ok := dnsLayer.(*layers.DNS)
			if !ok || !dns.QR {
				continue
			}

			for _, ans := range dns.Answers {

				if ans.Type != layers.DNSTypeA {
					continue
				}

				if len(ans.IP) == 0 {
					continue
				}

				name := strings.ToLower(
					strings.TrimSuffix(string(ans.Name), "."),
				)

				ttl := ans.TTL
				if ttl == 0 {
					ttl = 60
				}
				addr := ans.IP
				log.Printf("域名: %v -> IP: %v", name, addr)
				onDNS(name, addr, ttl)
			}
		}
	}
}
