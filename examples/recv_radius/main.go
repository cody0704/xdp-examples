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

"github.com/cilium/ebpf/link"
ebpf "github.com/cody0704/xdp-examples/examples/recv_radius/xdp_sock"
"layeh.com/radius"
)

var limits = make(chan *radiusPacket, 100000)
var sendCount, recCount int

type radiusPacket struct {
payload []byte
srcAddr *net.UDPAddr
}

func radius_handle(conn *net.UDPConn) {
for pkt := range limits {
if packet, err := radius.Parse(pkt.payload, []byte("123456")); err == nil {
if response, err := packet.Response(radius.CodeAccountingResponse).Encode(); err == nil {
_, err = conn.WriteToUDP(response, pkt.srcAddr)
if err != nil {
log.Printf("error sending response: %v", err)
} else {
sendCount++
}
}
}
}
}

func main() {
var port int64
var linkName string
log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

flag.StringVar(&linkName, "linkname", "", "The network link on which rebroadcast should run on.")
flag.Int64Var(&port, "port", 0, "Port Number")
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

if port < 1 || port > 65535 {
log.Panic("port must be between 1 and 65535")
}

// Load the XDP eBPF program that passes matching UDP packets to the kernel stack.
prog, err := ebpf.NewUDPPortProgram(uint32(port), nil)
if err != nil {
fmt.Printf("error: failed to create xdp program: %v\n", err)
return
}
defer prog.Close()

// Attach the XDP program to the network interface.
l, err := link.AttachXDP(link.XDPOptions{
Program:   prog,
Interface: Ifindex,
})
if err != nil {
fmt.Printf("error: failed to attach xdp program to interface: %v\n", err)
return
}
defer l.Close()

// Listen for UDP packets on the specified port.
addr := &net.UDPAddr{Port: int(port)}
conn, err := net.ListenUDP("udp4", addr)
if err != nil {
fmt.Printf("error: failed to listen on UDP port %d: %v\n", port, err)
return
}
defer conn.Close()

go radius_handle(conn)
go func() {
for {
log.Println("Recv:", recCount, "Send", sendCount)
time.Sleep(time.Second * 1)
}
}()

log.Println("Start UDP Server: linkname:", linkName, "Port:", port)
c := make(chan os.Signal, 1)
signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

go func() {
<-c
l.Close()
conn.Close()
os.Exit(1)
}()

buf := make([]byte, 65536)
for {
n, srcAddr, err := conn.ReadFromUDP(buf)
if err != nil {
fmt.Printf("error: %v\n", err)
return
}
if n > 0 {
payload := make([]byte, n)
copy(payload, buf[:n])
limits <- &radiusPacket{payload: payload, srcAddr: srcAddr}
recCount++
}
}
}
