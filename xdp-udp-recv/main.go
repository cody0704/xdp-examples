// Copyright 2019 Asavie Technologies Ltd. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

/*
dumpframes demostrates how to receive frames from a network link using
github.com/asavie/xdp package, it sets up an XDP socket attached to a
particular network link and dumps all frames it receives to standard output.
*/
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cody0704/xdp-examples/ebpf"

	"github.com/asavie/xdp"
)

// go:generate echo helloworld

var limits = make(chan []byte, 10000)

func udpprocess() {
	for pktData := range limits {
		// fmt.Println(pktData)
		// SRC IP
		// fmt.Println(pktData[26:30])
		// DST IP
		// fmt.Println(pktData[30:34])
		// SRC PORT
		// fmt.Println(pktData[34:36])
		// DST PORT
		// fmt.Println(pktData[36:38])
		// PAYLOAD
		fmt.Println(time.Now().UnixMicro(), string(pktData[42:]))

	}
}

func main() {
	var linkName string
	var queueID int
	var protocol int64
	var port int64

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "ens19", "The network link on which rebroadcast should run on.")
	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Int64Var(&protocol, "ip-proto", 17, "If greater than 0 and less than or equal to 255, limit xdp bpf_redirect_map to packets with the specified IP protocol number.")
	flag.Int64Var(&port, "port", 8000, "Port Number")
	flag.Parse()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex := -1
	for _, iface := range interfaces {
		if iface.Name == linkName {
			Ifindex = iface.Index
			break
		}
	}
	if Ifindex == -1 {
		fmt.Printf("error: couldn't find a suitable network interface to attach to\n")
		return
	}

	var program *xdp.Program

	if port < 0 || port > 65565 {
		log.Panic("Out of Port")
	}

	// Create a new XDP eBPF program and attach it to our chosen network link.
	// program, err = ebpf.NewIPPortProgram(uint32(port), nil)
	if protocol == 0 {
		program, err = xdp.NewProgram(queueID + 1)
	} else {
		program, err = ebpf.NewIPProtoProgram(uint32(protocol), uint32(port), nil)
	}
	if err != nil {
		fmt.Printf("error: failed to create xdp program: %v\n", err)
		return
	}
	defer program.Close()
	if err := program.Attach(Ifindex); err != nil {
		fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
		return
	}
	defer program.Detach(Ifindex)

	// Create and initialize an XDP socket attached to our chosen network
	// link.
	xsk, err := xdp.NewSocket(Ifindex, queueID, &xdp.SocketOptions{
		NumFrames:              204800,
		FrameSize:              4096,
		FillRingNumDescs:       8192,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         8192,
		TxRingNumDescs:         64,
	})
	if err != nil {
		fmt.Printf("error: failed to create an XDP socket: %v\n", err)
		return
	}

	// Register our XDP socket file descriptor with the eBPF program so it can be redirected packets
	if err := program.Register(queueID, xsk.FD()); err != nil {
		fmt.Printf("error: failed to register socket in BPF map: %v\n", err)
		return
	}
	defer program.Unregister(queueID)

	go udpprocess()
	go udpprocess()
	go udpprocess()

	// go func() {
	// 	for {

	// 	}
	// }()
	for {
		// If there are any free slots on the Fill queue...
		if n := xsk.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			xsk.Fill(xsk.GetDescs(n))
		}
		// Wait for receive - meaning the kernel has
		// produced one or more descriptors filled with a received
		// frame onto the Rx ring queue.
		// log.Printf("waiting for frame(s) to be received...")
		numRx, _, err := xsk.Poll(-1)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			return
		}

		if numRx > 0 {
			// Consume the descriptors filled with received frames
			// from the Rx ring queue.
			rxDescs := xsk.Receive(numRx)
			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(rxDescs); i++ {
				// go func(i int) {
				pktData := xsk.GetFrame(rxDescs[i])
				limits <- pktData
				// }(i)
			}
		}
	}
}
