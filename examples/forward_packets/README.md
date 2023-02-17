## Forward Packets

Forwarding packets via XDP

- Linux

### Complie

```bash
# Ubuntu 20.04
# pwd: <project>/ebpf/udp
clang -O3 -g -Wall -target bpf -c forward_packets.c -o forward_packets.o -I/usr/include/ -I../include/
```

### Attach

```bash
# generic mode
ip link set dev lo xdpgeneric obj forward_packets.o sec xdp
# deattch
ip link set dev lo xdpgeneric off

# interface needs to support
# native mode
ip link set dev <interfaceNane> xdp obj forward_packets.o sec xdp
# deattch
ip link set dev <interfaceNane> xdp off
```

### Test

```
Step1.
[Sender](127.0.0.1)--->(127.0.0.1:7999, Interface: lo)[XDP]

Step2.
[XDP](192.168.249.107, Interface: eth0)--->(192.168.249.50:7999)[Receiver]
```

- XDP

```bash
ip link set dev lo xdpgeneric obj forward_packets.o sec xdp
```

- Receiver

```bash
nc -lu 192.168.249.50 7999
```

- Sender

```
nc -u 127.0.0.1 7999
```

## XDP Print

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

## Ref

1. https://github.com/zhao-kun/xdp-redirect
