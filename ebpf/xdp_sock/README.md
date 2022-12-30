## XDP Sock

Receive UDP directly via XDP

- Golang

### Build

```bash
cd <project>/ebpf/udp
go generate
```

### Run

- Server

```bash
go run main.go -linkname lo -port 6000
```

- Client

```bash
nc -u 127.0.0.1 6000
```
