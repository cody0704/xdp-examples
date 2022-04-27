VERSION ?= $(shell git describe --tags --always || git rev-parse --short HEAD)

compile-all:
	GOOS=linux GOARCH=amd64 go build -o bin/xdp-udp ./examples/xdp-udp
	GOOS=linux GOARCH=amd64 go build -o bin/xdp-udp ./examples/xdp-radius

compile-radius:
	GOOS=linux GOARCH=amd64 go build -o bin/xdp-udp -ldflags ./examples/xdp-radius

compile-udp:
	GOOS=linux GOARCH=amd64 go build -o bin/xdp-udp -ldflags ./examples/xdp-udp

clean:
	/bin/rm -rf ./bin