## XDP Sock

Receive UDP directly via XDP

- Golang

### Build

```bash
cd xdp_sock
go generate
```

### Run

```
[Sender](UDP Packet)---->(port: 6000)[XDP]---->[AF_XDP with Go]
```

- Server

```bash
go run main.go -linkname lo -port 6000
```

- Client

```bash
nc -u 127.0.0.1 6000
```
