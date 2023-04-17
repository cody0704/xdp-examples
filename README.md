# XDP-Examples

## Examples

- [x] - [Change Port](https://github.com/cody0704/xdp-examples/tree/master/examples/change_port)
- [x] - [RoundRobin Port Allocation](https://github.com/cody0704/xdp-examples/tree/master/examples/port_roundrobin)
- [ ] - Redirect CPU
- [ ] - Round Robin CPU Allocation
- [x] - [Forward Packets](https://github.com/cody0704/xdp-examples/tree/master/examples/forward_packets)
- [x] - [Network Tap](https://github.com/cody0704/xdp-examples/tree/master/examples/network_tap)
- [x] - [Receive udp using AF_XDP](https://github.com/cody0704/xdp-examples/tree/master/examples/recv_udp)
- [x] - [Receive radius using AF_XDP](https://github.com/cody0704/xdp-examples/tree/master/examples/recv_radius)
- [ ] - Send Packet using AF_XDP

## Install

### Require

```bash
# Ubuntu 22.04
apt-get install linux-kernel-headers linux-headers-$(uname -r)
apt-get install libclang-dev llvm-dev autoconf libtool libelf-dev elfutils bpfcc-tools linux-tools-common gcc-multilib clang-12 libelf-dev strace tar bpfcc-tools gcc libbpf-dev

# Redhat 9
dnf install clang clang-devel llvm gcc libbpf xdp-tools bpftool kernel-devel kernel-headers glibc-devel.i686
```

### Tool

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@v0.9.3
```

### Link Correct Directory Name

```bash
# Ubuntu 20.04 or 22.04
ln -s /usr/bin/clang-12 /usr/bin/clang

# Ubuntu 20.04
ln -s /usr/include/asm-generic /usr/include/asm
```

## XDP Mode

```bash
$ ip link
```

ens19: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 `xdp` qdisc fq_codel state UP mode DEFAULT group default qlen 1000

- Native
- Offload
- Generic
