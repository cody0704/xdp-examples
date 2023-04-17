## Proxy

Forwarding packets via XDP Redirect

> Notice:
>
> Need to be in the same virtual network environment

- Linux

### Complie

```bash
# Ubuntu 20.04
# pwd: <project>/ebpf/udp
clang -O3 -g -Wall -target bpf -c forward_packets.c -o forward_packets.o -I/usr/include/ -I../../include/
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

> Notice: hw tx offload needs to be disabled

- lab env

```
VM1/UDP_Sender           VM2/XDP_Forward
-----------------        -------------------
|eth1:172.18.1.1|------->|eth1:172.18.1.254|        VM3/UDP_Receiver
-----------------        -------------------        --------------------
                         |      eth2       |------->|eth2:192.168.1.254|
                         -------------------        --------------------
```

- packet flow

```
1. [VM1:eth1]172.18.1.1:31612 --> [VM2:eth1]172.18.1.254:7999

                          ⇩ (Modify it to the following direction through XDP)

2. [VM2:eth2]172.18.1.254:31612 --> [VM3:eth2]192.168.1.254:7999
```

1. VM2/XDP_Forward

```bash
ip link set dev eth1 xdpgeneric obj forward_packets.o sec xdp
```

2. Add or Update redirect rules

```bash
# go run forward_packets.go --saddr <SIP> --smac <SMAC> --daddr <DIP> --dmac <DMAC> --egress <IFID>
go run forward_packets.go --saddr 172.18.1.1 --smac 82:81:76:6a:09:90 --daddr 192.168.1.254 --dmac 8e:d2:cd:8c:57:12 --egress 3
```

3. VM3/Receiver

```bash
nc -lu 192.168.1.254 7999
```

4. VM1/Sender

```
nc -u 172.18.1.254 7999
```

## Ref

1. https://github.com/zhao-kun/xdp-redirect
2. https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting
3. https://www.geeksforgeeks.org/is-sizeof-for-a-struct-equal-to-the-sum-of-sizeof-of-each-member/
