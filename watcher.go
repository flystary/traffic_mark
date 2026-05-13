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

	_ = h.SetBPFFilter("udp src port 53")
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
				// 仅处理 A 记录 (IPv4)
				if ans.Type == layers.DNSTypeA && len(ans.IP) > 0 {
					name := strings.ToLower(strings.TrimSuffix(string(ans.Name), "."))

					// 执行回调
					onDNS(name, ans.IP, ans.TTL)
				}
			}
		}
	}
}
