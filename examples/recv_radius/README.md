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
[Sender](Radius Packet)---->(port: 1813)[XDP]---->[AF_XDP with Go]
```

- Server

```bash
go run main.go -linkname lo -port 1813
```

- Radius tool

<!-- TODO -->
