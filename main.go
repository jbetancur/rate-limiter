package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go rate_limiter rate_limiter.c -- -DPACKET_LIMIT=120000 -DRATE=5

import (
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type config struct {
	Interface string `env:"INTERFACE" envDefault:"ens33"`
	LogLevel  string `env:"LOG_LEVEL" envDefault:"info"`
}

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

type metrics struct {
	pktCounter     *prometheus.GaugeVec
	pktDropCounter *prometheus.GaugeVec
}

func NewMetrics(reg prometheus.Registerer) *metrics {
	m := &metrics{
		pktCounter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "packet_counter",
				Help: "Total number of packets by ip",
			},
			[]string{"source_ip", "network_interface"},
		),
		pktDropCounter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "packet_drop_counter",
				Help: "Total number of dropped packets by ip",
			},
			[]string{"source_ip", "network_interface"},
		),
	}

	reg.MustRegister(m.pktCounter, m.pktDropCounter)

	return m
}

func serveMetrics() *metrics {
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)
	pMux := http.NewServeMux()

	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	pMux.Handle("/metrics", promHandler)

	go func() {
		log.Fatal(http.ListenAndServe(":8080", pMux))
	}()

	return m
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatal("Unable to parse environment variables: ", err)
	}

	// Set log level
	level, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		log.Fatalf("Invalid log level: %s", err)
	}

	log.SetLevel(level)

	m := serveMetrics()

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

	ifname := cfg.Interface
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

	log.Infof("Rate limiting %s..", ifname)

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
				ipStr := ip.String()

				log.Debugf("SourceIP: %s, Value: %+v", ipStr, value)

				// Update Prometheus counter with the packet count for the source IP
				m.pktCounter.WithLabelValues(ipStr, ifname).Add(float64(value.PktCounter))

				// Update Prometheus counter with the packet drop count for the source IP
				m.pktDropCounter.WithLabelValues(ipStr, ifname).Add(float64(value.PktDropCounter))

			}
			if err := iter.Err(); err != nil {
				log.Fatal("Iteration error:", err)
			}
		case <-stop:
			log.Info("Received signal, exiting..")

			return
		}
	}
}
