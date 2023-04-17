package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/asavie/xdp"
	ebpf "github.com/cody0704/xdp-examples/examples/recv_udp/xdp_sock"
)

var limits = make(chan []byte)
var count int

func udpprocess() {
	for pktData := range limits {
		// PAYLOAD
		_ = pktData
		count++
		log.Println(count)
		// log.Print(
		// 	"SrcIP: ", net.IP(pktData[26:30]).String(), ", SrcPort: ", int(pktData[34])*256+int(pktData[35]),
		// 	", DstIP: ", net.IP(pktData[30:34]).String(), ", DstPort: ", int(pktData[36])*256+int(pktData[37]),
		// 	", Data: ", string(pktData[42:]),
		// )
	}
}

func main() {
	var linkName string
	var queueID int
	var port int64
	var multipleReceiver int

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "", "The network link on which rebroadcast should run on.")
	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Int64Var(&port, "port", 0, "Port Number")
	flag.IntVar(&multipleReceiver, "multiple", 1, "Start multiple receivers")
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
	program, err = ebpf.NewUDPPortProgram(uint32(port), nil)
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

	for i := 0; i < multipleReceiver; i++ {
		go udpprocess()
	}

	log.Println("Start UDP Server: linkname:", linkName, "Port:", port)

	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		program.Detach(Ifindex)
		os.Exit(1)
	}()

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
				pktData := xsk.GetFrame(rxDescs[i])
				limits <- pktData
			}
		}
	}
}
