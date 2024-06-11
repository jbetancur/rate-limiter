package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go rate_limiter rate_limiter.c -- -DPACKET_LIMIT=10000 -DRATE=5

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

type config struct {
	Interface           string `env:"INTERFACE" envDefault:"ens33"`
	DebugFilterSourceIP string `env:"DEBUG_FILTER_port"`
	LogLevel            string `env:"LOG_LEVEL" envDefault:"info"`
}

type PortKey struct {
	SrcIP   uint32
	SrcPort uint16
	Padding uint16 // Explicitly match the padding
}

type PacketState struct {
	Tokens          uint32
	LastRefill      uint64
	RateLimited     bool
	PktDropCounter  uint64
	ConfigLimit     uint64
	ConfigRate      uint64
	ActualRateLimit uint64
}

type CIDRKey struct {
	Network   uint32
	PrefixLen uint32
}

type Metric struct {
	SrcIP          uint32
	SrcPort        uint16
	PktDropCounter uint64
	PktCount       uint64
	Timestamp      uint64
}

type Metrics struct {
	rateLimited    *prometheus.GaugeVec
	pktDropCounter *prometheus.GaugeVec
	tokens         *prometheus.GaugeVec
}

// reverseByteOrder reverses the byte order of a 32-bit integer.
func reverseByteOrder(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

func newMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		rateLimited: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rate_limited",
				Help: "If the connection is being rate limited",
			},
			[]string{"connection", "network_interface", "cidr_exclusions"},
		),
		pktDropCounter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rate_limited_drops",
				Help: "Total number of dropped packets by connection",
			},
			[]string{"connection", "network_interface", "cidr_exclusions"},
		),
		tokens: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "rate_limited_tokens",
				Help: "Available tokens. Max tokens should be equal to the packet limit, but when 0 indicates the packets are rate limited",
			},
			[]string{"connection", "network_interface", "cidr_exclusions"},
		),
	}

	reg.MustRegister(m.rateLimited, m.pktDropCounter, m.tokens)

	return m
}

func serveMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg)
	pMux := http.NewServeMux()

	promHandler := promhttp.HandlerFor(reg, promhttp.HandlerOpts{})
	pMux.Handle("/metrics", promHandler)

	go func() {
		log.Fatal(http.ListenAndServe(":8080", pMux))
	}()

	return m
}

func boolToFloat64(b bool) float64 {
	if b {
		return 1.0
	}

	return 0.0
}

func fetchAndProcessMetrics(objs *rate_limiterObjects, m *Metrics, networkInterface string, cidrExclusions []string) {
	// Create an iterator for the map.
	iter := objs.Connections.Iterate()

	cidrString := strings.Join(cidrExclusions, ",")

	// Define variables to hold key and value.
	var key PortKey
	var value PacketState

	// Iterate over all key-value pairs in the map.
	for iter.Next(&key, &value) {
		ip := reverseByteOrder(key.SrcIP).String()
		keyedBy := fmt.Sprintf("%s:%d", ip, key.SrcPort)
		log.Debugf("Source: %s, Value: %+v", keyedBy, value)

		// Update Prometheus gauge with the packet count for the source port
		m.rateLimited.WithLabelValues(keyedBy, networkInterface, cidrString).Set(boolToFloat64(value.RateLimited))

		// Update Prometheus gauge with the packet drop count for the source port
		m.pktDropCounter.WithLabelValues(keyedBy, networkInterface, cidrString).Set(float64(value.PktDropCounter))

		// Update Prometheus gauge with the token count for the source port
		m.tokens.WithLabelValues(keyedBy, networkInterface, cidrString).Set(float64(value.Tokens))
	}

	if err := iter.Err(); err != nil {
		log.Fatal("Iteration error:", err)
	}
}

func run(networkInterface string) {
	m := serveMetrics()

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs rate_limiterObjects
	if err := loadRate_limiterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	defer objs.Close()

	// Add CIDR exclusions
	cidrExclusions := []string{
		"192.168.1.0/24",
		// "10.0.0.0/8",
		// Add more CIDR ranges as needed
	}
	if err := updateCIDRExclusions(&objs, cidrExclusions); err != nil {
		log.Fatalf("Updating CIDR exclusions: %s", err)
	}

	iface, err := net.InterfaceByName(networkInterface)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", networkInterface, err)
	}

	// Attach rate_limiter to the network interface.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.RateLimit,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}

	defer l.Close()

	log.Infof("Rate limiting %s...", networkInterface)

	// Periodically fetch metrics.
	// exit the program when interrupted.
	tick := time.Tick(time.Second / 2) // Adjusted for higher precision
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)

	for {
		select {
		case <-tick:
			go fetchAndProcessMetrics(&objs, m, networkInterface, cidrExclusions)
		case <-stop:
			log.Info("Received signal, exiting..")

			return
		}
	}
}

// Update the CIDR exclusions map in eBPF
func updateCIDRExclusions(objs *rate_limiterObjects, cidrList []string) error {
	for _, cidr := range cidrList {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
		}

		// Extract the network address in big-endian order
		var network uint32
		ipBytes := ip.To4()
		if ipBytes == nil {
			return fmt.Errorf("only IPv4 supported, got %s", cidr)
		}
		network = binary.BigEndian.Uint32(ipBytes)

		// Calculate prefix length
		prefixLen, _ := ipnet.Mask.Size()

		// Create the CIDR key
		key := CIDRKey{
			Network:   network,
			PrefixLen: uint32(prefixLen),
		}

		value := uint32(1) // Dummy value for map

		// Update the eBPF map
		err = objs.CidrExclusions.Put(key, value)
		if err != nil {
			return fmt.Errorf("failed to update CIDR exclusion map: %w", err)
		}
	}

	return nil
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

	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	run(cfg.Interface)
}
