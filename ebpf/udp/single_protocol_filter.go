package udp

import (
	"fmt"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate /root/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3

// NewIPProtoProgram returns an new eBPF that directs packets of the given ip protocol to to XDP sockets
func NewIPPortProgram(dest uint32, options *ebpf.CollectionOptions) (*xdp.Program, error) {
	spec, err := loadIpproto()
	if err != nil {
		return nil, err
	}

	if dest > 0 && dest <= 65535 {
		if err := spec.RewriteConstants(map[string]interface{}{"PORT": uint16(dest)}); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}

	var program ipprotoObjects
	if err := spec.LoadAndAssign(&program, options); err != nil {
		return nil, err
	}

	p := &xdp.Program{Program: program.XdpSockProg, Queues: program.QidconfMap, Sockets: program.XsksMap}
	return p, nil
}
