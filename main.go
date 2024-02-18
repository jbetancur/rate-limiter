package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	pktCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packet_counter",
			Help: "Total number of packets by ip",
		},
		[]string{"source_ip", "interface", "timestamp", "tokens"},
	)

	pktDropCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "packet_drop_counter",
			Help: "Total number of dropped packets by ip",
		},
		[]string{"source_ip", "interface", "timestamp", "tokens"},
	)
)

type PacketState struct {
	Tokens         uint32
	Timestamp      uint64
	PktCounter     uint32
	PktDropCounter uint32
}

// reverseByteOrder reverses the byte order of a 32-bit integer.
func reverseByteOrder(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func main() {
	// Register Prometheus metrics
	prometheus.MustRegister(pktCounter)
	prometheus.MustRegister(pktDropCounter)

	// Set debug logging
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)
	log.SetPrefix("DEBUG: ")

	// Expose Prometheus metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatal("HTTP server error: ", err)
		}
	}()

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs rate_limiterObjects
	if err := loadRate_limiterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	defer objs.Close()

	ifname := "ens33" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach rate_limiter to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.RateLimit,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}

	defer link.Close()

	log.Printf("start watching %s..", ifname)

	// Periodically fetch the packet counter from PktCount,
	// exit the program when interrupted.
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			// Create an iterator for the map.
			iter := objs.SourceIpMapping.Iterate()

			// Define variables to hold key and value.
			var key uint32
			var value PacketState

			// Iterate over all key-value pairs in the map.
			for iter.Next(&key, &value) {
				ip := reverseByteOrder(key)

				log.Printf("SourceIP: %s, Value: %+v", ip.String(), value)

				timestamp := strconv.FormatUint(value.Timestamp, 10)
				tokens := strconv.FormatUint(uint64(value.Tokens), 10)

				// Update Prometheus counter with the packet count for the source IP
				pktCounter.WithLabelValues(ip.String(), ifname, timestamp, tokens).Add(float64(value.PktCounter))

				// Update Prometheus counter with the packet drop count for the source IP
				pktDropCounter.WithLabelValues(ip.String(), ifname, timestamp, tokens).Add(float64(value.PktDropCounter))
			}
			if err := iter.Err(); err != nil {
				log.Fatal("Iteration error:", err)
			}
		case <-stop:
			log.Print("Received signal, exiting..")

			return
		}
	}
}
