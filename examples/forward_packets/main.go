package main

import (
	"encoding/binary"
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

func main() {
	var mapName string = "servers"
	path := bpf.MapPath(mapName)
	serversMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Load pinned map %s", path))
	}

	if serversMap == nil {
		log.Panic(errors.New("load pinned map from userspace before you use"))
	}

	saddr := InetAton("192.168.249.107")
	daddr := InetAton("192.168.249.50")
	log.Println("SIP", saddr)
	log.Println("DIP", daddr)
	var lb RedirectMetaMap = RedirectMetaMap{
		SourceAddr: saddr,
		DestAddr:   daddr,
		IfIndex:    5,
	}

	sendMac := "82:81:76:6a:09:90"
	smac, err := net.ParseMAC(sendMac)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Invalid mac %s address, convert error", sendMac).Error())
	}
	copy(lb.Smac[:], smac)

	recvMac := "8e:d2:cd:8c:57:12"
	dmac, err := net.ParseMAC(recvMac)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Invalid mac %s address, convert error", recvMac).Error())
	}
	copy(lb.Dmac[:], dmac)

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
