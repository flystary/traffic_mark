package main

import "github.com/cilium/ebpf"

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
