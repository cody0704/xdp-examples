package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	var linkName string
	var count int
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&linkName, "linkname", "", "The network link on which rebroadcast should run on.")
	flag.IntVar(&count, "count", 100000, "send total packets")
	flag.Parse()

	conn, err := open(linkName)
	if err != nil {
		log.Panic(err)
	}

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Id:       0,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP("192.168.123.100"),
		DstIP:    net.ParseIP("192.168.123.200"),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(6000),
		DstPort: layers.UDPPort(6000),
	}

	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Panic(err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, ip, udp, gopacket.Payload([]byte("Hello")))
	// err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(response))
	if err != nil {
		panic(err)
	}

	for i := 0; i < count; i++ {
		if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: net.ParseIP("192.168.123.200")}); err != nil {
			log.Println(err)
		}
	}

}

func open(ifName string) (net.PacketConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("Failed open socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW): %s", err)
	}
	syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)

	if ifName != "" {
		_, err := net.InterfaceByName(ifName)
		if err != nil {
			return nil, fmt.Errorf("Failed to find interface: %s: %s", ifName, err)
		}
		syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
	}

	conn, err := net.FilePacketConn(os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}
