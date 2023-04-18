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

//go:generate clang -O3 -g -Wall -target bpf -c network_tap.c -o network_tap.o -I/usr/include/ -I../../include/

var (
	ingress int
	egress  int
)

func main() {
	flag.IntVar(&ingress, "ingress", 1, "--ingress 1")
	flag.IntVar(&egress, "egress", 2, "--egress 2")
	flag.Parse()

	var mapName string = "tx_if"
	path := bpf.MapPath(mapName)
	serversMap, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		log.Panic(errors.Wrapf(err, "Load pinned map %s", path))
	}

	if serversMap == nil {
		log.Panic(errors.New("load pinned map from userspace before you use"))
	}

	var u32ingress = uint32(ingress)
	var u32egress = uint32(egress)

	err = serversMap.Put(u32ingress, u32egress)
	// err = serversMap.Update(u32ingress, u32egress, ebpf.UpdateAny)
	if err != nil {
		log.Panic(errors.Wrapf(err, "update ingress %d , egress %d", u32ingress, u32egress).Error())
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
