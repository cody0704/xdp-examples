package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"

	"github.com/cilium/ebpf"
)

const bpfGlobalsPath = "/sys/fs/bpf/tc/globals/"

//go:generate clang -O3 -g -Wall -target bpf -c forward_packets.c -o forward_packets.o -I/usr/include/ -I../../include/

type RedirectMetaMap struct {
	SourceAddr uint32
	DestAddr   uint32
	Smac       [6]uint8
	Dmac       [6]uint8
	IfIndex    uint32
}

var (
	saddr  string
	daddr  string
	smac   string
	dmac   string
	egress int
)

func main() {
	flag.StringVar(&saddr, "saddr", "", "--saddr 192.168.0.1")
	flag.StringVar(&daddr, "daddr", "", "--daddr 192.168.0.2")
	flag.StringVar(&smac, "smac", "", "--smac 12:23:34:45:56:67")
	flag.StringVar(&dmac, "dmac", "", "--dmac 22:33:44:55:66:77")
	flag.IntVar(&egress, "egress", 1, "--egress 1")
	flag.Parse()

	var mapName string = "servers"
	path := bpfGlobalsPath + mapName
	serversMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		log.Panicf("Load pinned map %s: %v", path, err)
	}

	if serversMap == nil {
		log.Panic("load pinned map from userspace before you use")
	}

	u32saddr := InetAton(saddr)
	u32daddr := InetAton(daddr)
	var lb RedirectMetaMap = RedirectMetaMap{
		SourceAddr: u32saddr,
		DestAddr:   u32daddr,
		IfIndex:    uint32(egress),
	}

	u8smac, err := net.ParseMAC(smac)
	if err != nil {
		log.Panicf("Invalid mac %s address, convert error: %v", smac, err)
	}
	copy(lb.Smac[:], u8smac)

	u8dmac, err := net.ParseMAC(dmac)
	if err != nil {
		log.Panicf("Invalid mac %s address, convert error: %v", dmac, err)
	}
	copy(lb.Dmac[:], u8dmac)

	var i uint32 = 0
	err = serversMap.Put(i, lb)
	// err = serversMap.Update(i, lb, ebpf.UpdateAny)
	if err != nil {
		log.Panicf("update key %d , value %+v: %v", 0, lb, err)
	}
}

// InetAton convert a human readable ipv4 address to inet address
func InetAton(addr string) uint32 {
	ip := net.ParseIP(addr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	return binary.LittleEndian.Uint32(ip)
}
