package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	flushInterval = time.Duration(1) * time.Second
	maxQueueSize  = 1000000
	UDPPacketSize = 1500
)

var address string
var bufferPool sync.Pool
var ops uint64 = 0
var total uint64 = 0
var flushTicker *time.Ticker
var nbWorkers int

func init() {
	flag.StringVar(&address, "addr", ":8181", "Address of the UDP server to test")
	flag.IntVar(&nbWorkers, "concurrency", runtime.NumCPU(), "Number of workers to run in parallel")
}

type message struct {
	addr   net.Addr
	msg    []byte
	length int
}

type messageQueue chan message

func (mq messageQueue) enqueue(m message) {
	mq <- m
}

func (mq messageQueue) dequeue() {
	for m := range mq {
		handleMessage(m.addr, m.msg[0:m.length])
		bufferPool.Put(m.msg)
	}
}

var mq messageQueue

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Parse()

	bufferPool = sync.Pool{
		New: func() interface{} { return make([]byte, UDPPacketSize) },
	}
	mq = make(messageQueue, maxQueueSize)
	listenAndReceive(nbWorkers)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			atomic.AddUint64(&total, ops)
			log.Printf("Total ops %d", total)
			os.Exit(0)
		}
	}()

	flushTicker = time.NewTicker(flushInterval)
	for range flushTicker.C {
		log.Printf("Ops/s %f", float64(ops)/flushInterval.Seconds())
		atomic.AddUint64(&total, ops)
		atomic.StoreUint64(&ops, 0)
	}
}

func listenAndReceive(maxWorkers int) error {
	c, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	for i := 0; i < maxWorkers; i++ {
		go mq.dequeue()
		go receive(c)
	}
	return nil
}

// receive accepts incoming datagrams on c and calls handleMessage() for each message
func receive(c net.PacketConn) {
	defer c.Close()

	for {
		msg := bufferPool.Get().([]byte)
		nbytes, addr, err := c.ReadFrom(msg[0:])
		if err != nil {
			log.Printf("Error %s", err)
			continue
		}
		mq.enqueue(message{addr, msg, nbytes})
	}
}

func handleMessage(addr net.Addr, msg []byte) {
	// Do something with message
	atomic.AddUint64(&ops, 1)
}
