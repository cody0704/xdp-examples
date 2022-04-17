# XDP-Examples

* OS: Ubuntu20.04
* Kernel: 5.4

## Install

### Require

```bash
apt-get install libclang-dev llvm-dev autoconf libtool linux-kernel-headers kernel-package libelf-dev elfutils bpfcc-tools linux-tools-common gcc-multilib clang-12 libelf-dev strace tar bpfcc-tools linux-headers-$(uname -r) gcc
```

### Tool

```bash
go install github.com/cilium/ebpf/cmd/bpf2go@v0.4.0
```

### Link Correct Directory Name

```bash
ln -s /usr/bin/clang-12 /usr/bin/clang
ln -s /usr/include/asm-generic /usr/include/asm
```

## Examples

### udp_recv

* Server

```bash
go run main.go -linkname lo -port 6000
```

* Client

```bash
echo "Hello XDP" > /dev/udp/localhost/6000
```