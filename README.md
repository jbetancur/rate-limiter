## Compile & Run
make compule
make run

## Appendix

### simulate
#### on target
sudo sysctl net.core.somaxconn=8192 # 4096 default
sudo apt install python3-pip
python3 -m pip install simple_http_server
python3 -m http.server 9000
htop

#### on source
sudo sysctl net.ipv4.ip_local_port_range="15000 61000"
ulimit -n 100000 
sudo apt install wrk bmon

OUCH
wrk -t48 -c1000000 -d30s http://10.0.60.23:9000 

### DEBUG
sudo cat /sys/kernel/debug/tracing/trace_pipe

### Build
clang -O2 -target bpf -c rate_limiter.c -o rate_limiter.o

### Attach/Detach
sudo ip link set dev ens33 xdp obj rate_limiter.o sec rate_limiter
 sudo ip link set dev ens33 xdp off

### Tests
Without
wrk -t48 -c10000 -d30s http://10.0.60.23:8000/hello
100% CPU all 4 cores
Memory no impact

With
wrk -t48 -c25000 -d30s http://10.0.60.23:8000/hello
2-4% CPU all 4 cores
Memory no impact

wrk -t48 -c50000 -d30s http://10.0.60.23:8000/hello
noticable slow down slow os crahed ssh
Memory no impact

## Readings
https://jgam.medium.com/rate-limiter-token-bucket-algorithm-efd86758c8ee
https://himanshu-007.medium.com/simple-rate-limiter-in-golang-using-token-bucket-algorithm-388d0596d1e4
https://www.byos.io/blog/denial-of-service-attack-prevention
https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go

## Maths
10GB = 1250 MB/s
1250000000 B/s
