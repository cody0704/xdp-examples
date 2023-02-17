package main

import (
	"encoding/binary"
	"flag"
	"log"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
)

type RedirectMetaMap struct {
	SourceAddr uint32
	DestAddr   uint32
	Smac       [6]uint8
	Dmac       [6]uint8
	IfIndex    uint32
}

var (
	saddr string
	daddr string
	smac  string
	dmac  string
)

func main() {
	flag.StringVar(&saddr, "saddr", "", "--saddr 192.168.0.1")
	flag.StringVar(&daddr, "daddr", "", "--daddr 192.168.0.2")
	flag.StringVar(&smac, "smac", "", "--smac 12:23:34:45:56:67")
	flag.StringVar(&dmac, "dmac", "", "--dmac 22:33:44:55:66:77")
	flag.Parse()

	var mapName string = "servers"
	path := bpf.MapPath(mapName)
	serversMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Load pinned map %s", path))
	}

	if serversMap == nil {
		log.Panic(errors.New("load pinned map from userspace before you use"))
	}

	u32saddr := InetAton(saddr)
	u32daddr := InetAton(daddr)
	var lb RedirectMetaMap = RedirectMetaMap{
		SourceAddr: u32saddr,
		DestAddr:   u32daddr,
		IfIndex:    5,
	}

	u8smac, err := net.ParseMAC(smac)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Invalid mac %s address, convert error", smac).Error())
	}
	copy(lb.Smac[:], u8smac)

	u8dmac, err := net.ParseMAC(dmac)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Invalid mac %s address, convert error", dmac).Error())
	}
	copy(lb.Dmac[:], u8dmac)

	var i uint32 = 0
	err = serversMap.Put(i, lb)
	// err = serversMap.Update(i, lb, ebpf.UpdateAny)
	if err != nil {
		log.Panic(errors.Wrapf(err, "update key %d , value %+v", 0, lb).Error())
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
