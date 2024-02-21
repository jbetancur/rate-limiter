## Rate Limiting Logic

- When a packet arrives, the rate_limit function checks if this is a valid IPV4 packet 
- The packet header is read for the source IP address
- The IP addess is added to the packet_state map
- If the IP address is not found in the map, it initializes a new entry in the map with the maximum number of tokens and other necessary information.
- This limiter uses the Token Bucket algorithm
- If tokens are available for the IP address, it decrements the token coun (PACKET_LIMIT). If no tokens are available, it checks if enough time has elapsed (RATE) to refill the bucket. If not, it drops the packet.
- The rate limit is calculated based on the configured packet limit and rate, and it's updated in real-time if it changes via configuration.

## Architecture

## Compile & Run
```sh
make compule
make run
```

## Load Testing

### Configuration
VM 4CPU
8GB Memory
10G NIC


### Simulate a DoS without rate limiting

This should saturate the target. Make sure this is a formidable multicore test machine.

Note: cpu threads depends on test system. e.g. 16cpu = -t32

```sh
ulimit -n 100000
wrk -t32 -c100000 -d600s http://10.0.60.23:8000/hello
```

### Simulate a DoS with rate limiting 

We are going to set our rate limited in main.go to the following:

 -DPACKET_LIMIT=120000 -DRATE=5

#### Start the twest web app

```sh
make testapp
```

#### Start the rate limiter
In another tab or terminal start the rate limiter

```sh
make run
```

#### On another machine start the loadtst

```sh
wrk -t16 -c100000 -d600s http://10.0.60.23:8000/hello
```

## Monitoring

http://ipaddress:9090/

The following guages are available:
sort_desc(rate_limited)
sort_desc(rate_limited_drops)
sort_desc(rate_limited_tokens)

You can access CPU usage as such:
100 * avg(1 - rate(node_cpu_seconds_total{mode="idle"}[1m]))

### Install Prometheus

```sh
...
sudo vim /etc/prometheus/prometheus.yml
```

Add a new target under job name `prometheus`

```sh
...
    static_configs:
      - targets: ['localhost:8080']
      ...
```

### Install Grafana

```sh
# Install
sudo apt-get install -y apt-transport-https software-properties-common wget
sudo mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | sudo tee /etc/apt/keyrings/grafana.gpg > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com beta main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
# Updates the list of available packages
sudo apt-get update
# Installs the latest OSS release:
sudo apt-get install grafana
 # Start
sudo systemctl daemon-reload
sudo systemctl start grafana-server
sudo systemctl status grafana-server
sudo systemctl enable grafana-server.service
```

## Appendix

### simulate
#### on target
sudo sysctl net.core.somaxconn=8192 # 4096 default
ulimit -n 100000
make testapp

#### on source
sudo sysctl net.ipv4.ip_local_port_range="15000 61000"
ulimit -n 100000
sudo apt install wrk bmon

### DEBUG
sudo cat /sys/kernel/debug/tracing/trace_pipe

### Build
clang -O2 -target bpf -c rate_limiter.c -o rate_limiter.o

### Attach/Detach
sudo ip link set dev ens33 xdp obj rate_limiter.o sec rate_limiter
sudo ip link set dev ens33 xdp off

## Readings
https://jgam.medium.com/rate-limiter-token-bucket-algorithm-efd86758c8ee
https://himanshu-007.medium.com/simple-rate-limiter-in-golang-using-token-bucket-algorithm-388d0596d1e4
https://www.byos.io/blog/denial-of-service-attack-prevention
https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go

## Maths
10GB = 1250 MB/s
1250000000 B/s
