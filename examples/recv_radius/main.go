package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	ebpf "github.com/cody0704/xdp-examples/examples/recv_radius/xdp_sock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"layeh.com/radius"
)

var limits = make(chan []byte, 100000)
var xsk *xdp.Socket
var Ifindex int
var queueID int
var sendCount, recCount int

func radius_handle() {
	for pktData := range limits {
		var payload = pktData[42:]
		if packet, err := radius.Parse(payload, []byte("123456")); err == nil {
			if response, err := packet.Response(radius.CodeAccountingResponse).Encode(); err == nil {
				var srcMAC = net.HardwareAddr(pktData[:6])
				var srcIP = net.IP(pktData[26:30])
				var srcPort = int(pktData[34])*256 + int(pktData[35])
				var dstMAC = net.HardwareAddr(pktData[6:12])
				var dstIP = net.IP(pktData[30:34])
				var dstPort = int(pktData[36])*256 + int(pktData[37])

				// log.Print(
				// 	"SrcMac:", srcMAC, ", DstMac:", dstMAC,
				// 	"SrcIP: ", srcIP, ", SrcPort: ", srcPort,
				// 	", DstIP: ", dstIP, ", DstPort: ", dstPort,
				// )

				eth := &layers.Ethernet{
					SrcMAC:       srcMAC,
					DstMAC:       dstMAC,
					EthernetType: layers.EthernetTypeIPv4,
				}
				ip := &layers.IPv4{
					Version:  4,
					IHL:      5,
					TTL:      64,
					Id:       0,
					Protocol: layers.IPProtocolUDP,
					SrcIP:    dstIP,
					DstIP:    srcIP,
				}
				udp := &layers.UDP{
					SrcPort: layers.UDPPort(dstPort),
					DstPort: layers.UDPPort(srcPort),
				}
				udp.SetNetworkLayerForChecksum(ip)

				buf := gopacket.NewSerializeBuffer()
				opts := gopacket.SerializeOptions{
					FixLengths:       true,
					ComputeChecksums: true,
				}

				err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(response))
				if err != nil {
					panic(err)
				}
				frameLen := len(buf.Bytes())

				descs := xsk.GetDescs(1)
				frameLen = copy(xsk.GetFrame(descs[0]), buf.Bytes())
				descs[0].Len = uint32(frameLen)
				xsk.Transmit(descs)
				sendCount++
			}
		}
	}
}

func main() {
	var port int64
	var linkName string
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "", "The network link on which rebroadcast should run on.")
	flag.IntVar(&queueID, "queueid", 0, "The ID of the Rx queue to which to attach to on the network link.")
	flag.Int64Var(&port, "port", 0, "Port Number")
	flag.Parse()

	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("error: failed to fetch the list of network interfaces on the system: %v\n", err)
		return
	}

	Ifindex = -1
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
	xsk, err = xdp.NewSocket(Ifindex, queueID, &xdp.SocketOptions{
		NumFrames:              8192,
		FrameSize:              2048,
		FillRingNumDescs:       2048,
		CompletionRingNumDescs: 64,
		RxRingNumDescs:         1024,
		TxRingNumDescs:         1024,
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

	go radius_handle()
	go func() {
		for {
			log.Println("Recv:", recCount, "Send", sendCount)
			time.Sleep(time.Second * 1)
		}
	}()

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
		// if n := xsk.NumFreeFillSlots(); n > 0 {
		// 	// ...then fetch up to that number of not-in-use
		// 	// descriptors and push them onto the Fill ring queue
		// 	// for the kernel to fill them with the received
		// 	// frames.

		// 	xsk.Fill(xsk.GetDescs(n))
		// }
		xsk.Fill(xsk.GetDescs(xsk.NumFreeFillSlots()))
		// log.Println("Fill")
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
			descs := xsk.Receive(numRx)
			// Print the received frames and also modify them
			// in-place replacing the destination MAC address with
			// broadcast address.
			for i := 0; i < len(descs); i++ {
				pktData := xsk.GetFrame(descs[i])
				limits <- pktData
				recCount++
			}
		}
	}
}
