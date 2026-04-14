package xdp_sock

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// go generate requires appropriate linux headers in included (-I) paths.
// See accompanying Makefile + Dockerfile to make updates.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 ipproto single_udp_port.c -- -I/usr/include/ -nostdinc -O3

// NewUDPPortProgram loads an XDP eBPF program that passes UDP packets on the
// given port to the kernel network stack. The returned program must be attached
// using link.AttachXDP and closed when no longer needed.
func NewUDPPortProgram(dest uint32, options *ebpf.CollectionOptions) (*ebpf.Program, error) {
	if dest < 1 || dest > 65535 {
		return nil, fmt.Errorf("port must be between 1 and 65535")
	}

	spec, err := loadIpproto()
	if err != nil {
		return nil, err
	}

	if err := spec.Variables["PORT"].Set(uint16(dest)); err != nil {
		return nil, fmt.Errorf("setting PORT variable: %w", err)
	}

	var objs ipprotoObjects
	if err := spec.LoadAndAssign(&objs, options); err != nil {
		return nil, err
	}

	return objs.XdpSockProg, nil
}
