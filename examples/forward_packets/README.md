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

- lab env

```
PVE Node
----------------------------------------------------------------
| VM1                           VM2                            |
| --------------------------        -------------------------- |
| |  [vmbr5]eth1 (MAC=X1)  |<-------|  [vmbr5]eth1 (MAC=X2)  | |
| --------------------------        -------------------------- |
----------------------------------------------------------------
```

- packet flow

```
1. [UDP_Send]127.0.0.1:1234 --> [XDP_Recv]127.0.0.1:7999

                       ⇩ (Modify it to the following direction through XDP)

2. [XDP_Recv]192.168.249.107:1234 --> [UDP_Recv]192.168.249.50:7999
```

1. VM2/XDP

```bash
ip link set dev lo xdpgeneric obj forward_packets.o sec xdp
```

2. VM1/Receiver

```bash
nc -lu 192.168.249.50 7999
```

3. Add or Update redirect rule

```bash
go run main.go --saddr 192.168.249.107 --smac 82:81:76:6a:09:90 --daddr 192.168.249.50 --dmac 8e:d2:cd:8c:57:12
```

4. VM2/Sender

```
nc -u 127.0.0.1 7999
```

## XDP Print

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

## XDP Struct and golang Struct size

If you execute main.go and see the following warning

```
can't marshal value: main.RedirectMetaMap doesn't marshal to 24 bytes
```

You must have modified the structure in xdp prog, please refer to the [article](https://www.geeksforgeeks.org/is-sizeof-for-a-struct-equal-to-the-sum-of-sizeof-of-each-member/)

## Ref

1. https://github.com/zhao-kun/xdp-redirect
2. https://github.com/xdp-project/xdp-tutorial/tree/master/packet03-redirecting
3. https://www.geeksforgeeks.org/is-sizeof-for-a-struct-equal-to-the-sum-of-sizeof-of-each-member/
