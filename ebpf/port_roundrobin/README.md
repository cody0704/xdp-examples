## Change Port

Round-Robin Port Allocation

- Linux

### Complie

```bash
# Redhat 9
# pwd: <project>/ebpf/udp
clang -O3 -g -Wall -target bpf -c <filename>.c -o <filename>.o -I/usr/include/ -I../include/ -I/usr/lib64/clang/14.0.6/include

# Ubuntu 20.04
clang -O3 -g -Wall -target bpf -c roundrobin_port.c -o roundrobin_port.o -I/usr/include/ -I../include/
```

### Attach

```bash
# generic mode
ip link set dev lo xdpgeneric obj roundrobin_port.o sec xdp
# deattch
ip link set dev lo xdpgeneric off

# interface needs to support
# native mode
ip link set dev <interfaceNane> xdp obj roundrobin_port.o sec xdp
# deattch
ip link set dev <interfaceNane> xdp off
```

### Test

```
                                 ┌----> (port: 6000)[Receiver]
[Sender](port:5999) ---(5999)[XDP]----> (port: 6001)[Receiver]
                                 └----> (port: 6002)[Receiver]
```

- XDP

```bash
ip link set dev lo xdpgeneric obj roundrobin_port.o sec xdp
```

- Receiver

```bash
nc -lu 127.0.0.1 6000
nc -lu 127.0.0.1 6001
nc -lu 127.0.0.1 6002
```

- Sender

```
nc -u 127.0.0.1 5999
```
