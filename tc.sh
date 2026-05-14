#!/bin/bash
iface=ens2f2

tc qdisc show dev $iface clsact
tc qdisc del dev $iface clsact
tc qdisc add dev $iface clsact
tc filter replace dev $iface ingress bpf da obj trafficmark_x86_bpfel.o sec classifier/ingress
tc filter replace dev $iface egress bpf da obj trafficmark_x86_bpfel.o sec classifier/egress
