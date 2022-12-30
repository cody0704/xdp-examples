## Change Port

Directly change UDP receiving port via XDP

- Linux

### Complie

```bash
# Redhat 9
# pwd: <project>/ebpf/udp
clang -O3 -g -Wall -target bpf -c <filename>.c -o <filename>.o -I/usr/include/ -I./include -I/usr/lib64/clang/14.0.6/include
```

### Attach

```bash
# generic mode
ip link set dev lo xdpgeneric obj change_port.o sec xdp
# deattch
ip link set dev lo xdpgeneric off

# interface needs to support
# native mode
ip link set dev <interfaceNane> xdp obj change_port.o sec xdp
# deattch
ip link set dev <interfaceNane> xdp off
```

### Test

```
[Sender](port:5999) ---(5999)[XDP](6000)---> (port: 6000)[Receiver]
```

- XDP

```bash
ip link set dev lo xdpgeneric obj change_port.o sec xdp
```

- Receiver

```bash
nc -lu 127.0.0.1 6000
```

- Sender

```
nc -u 127.0.0.1 5999
```
