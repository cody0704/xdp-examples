## Forward Packets

Forwarding packets via XDP Redirect

> Notice:
>
> Need to be in the same virtual network environment

- Linux

### Complie

```bash
# Ubuntu 20.04
# pwd: <project>/ebpf/udp
clang -O3 -g -Wall -target bpf -c network_tap.c -o network_tap.o -I/usr/include/ -I../../include/
```

### Attach

```bash
# generic mode
ip link set dev lo xdpgeneric obj network_tap.o sec xdp
# deattch
ip link set dev lo xdpgeneric off

# interface needs to support
# native mode
ip link set dev <interfaceNane> xdp obj network_tap.o sec xdp
# deattch
ip link set dev <interfaceNane> xdp off
```

### Test

> Notice: hw tx offload needs to be disabled

- lab env

```
VM1/UDP_Sender           VM2/XDP_Forward
-----------------        -------------------
|eth1:172.18.1.1|------->|eth1:172.18.1.254|        VM3/TCPDUMP(Promiscuous Mode)
-----------------        -------------------        --------
VM4/UDP_Sender       ┌-->|      eth2       |------->| eth2 |
-----------------    |   -------------------        --------
|eth3:172.18.2.1|----┘                            VM5/TCPDUMP(Promiscuous Mode)
-----------------        -------------------        --------
                         |      eth4       |------->| eth4 |
                         -------------------        --------
```

- packet flow

```
# Traffic 1
1. [VM1:eth1]172.18.1.1:31612 --> [VM2:eth1]172.18.1.254:7999
2. [VM2:eth2] --> [VM3]TCPDUMP
3. [VM3]TCPDUMP: 172.18.1.1:31612 --> 172.18.1.254:7999

# Traffic 2
1. [VM4:eth1]172.18.2.1:31612 --> [VM2:eth3]172.18.2.254:7999
2. [VM2:eth2] --> [VM5]TCPDUMP
3. [VM5]TCPDUMP: 172.18.2.1:31612 --> 172.18.2.254:7999
```

1. VM2/XDP

```bash
ip link set dev eth1 xdpgeneric obj forward_packets.o sec xdp
```

2. VM1/Receiver

```bash
nc -lu 192.168.249.50 7999
```

3. Add or Update redirect rule

```bash
# go run network_tap.go --ingress <IN_IFID> -egress <OUT_IFID>
go run network_tap.go --ingress 1 --egress 2
```

| ID  | ingress | egress |
| --- | ------- | ------ |
| 1   | 1       | 2      |
| 2   | 3       | 4      |

4. VM2/Sender

```
nc -u 127.0.0.1 7999
```

## XDP Track

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

## Ref

1. https://github.com/zhao-kun/xdp-redirect
2. https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting
3. https://www.geeksforgeeks.org/is-sizeof-for-a-struct-equal-to-the-sum-of-sizeof-of-each-member/
