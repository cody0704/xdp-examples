# XDP-Examples

## Install

### Require

```bash
# Ubuntu 22.04
apt-get install linux-kernel-headers linux-headers-$(uname -r)
apt-get install libclang-dev llvm-dev autoconf libtool libelf-dev elfutils bpfcc-tools linux-tools-common gcc-multilib clang-12 libelf-dev strace tar bpfcc-tools gcc

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

## Examples

- [xdp sock](https://github.com/cody0704/xdp-examples/tree/master/ebpf/xdp_sock)
- [change port](https://github.com/cody0704/xdp-examples/tree/master/ebpf/change_port)
