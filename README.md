# netkat

netcat version using raw sockets to avoid iptables and/or other OS filtering mechanisms.

## Install

```sh
make build
```

## Usage

It requires root privileges:

```sh
sudo ./bin/netkat
Usage: nk [options] [hostname] [port]

  -debug
        Debug
  -interface string
        Specify interface to use. Default interface with default route
  -listen
        Bind and listen for incoming connections
  -source-port int
        Specify source port to use
  -udp
        Use UDP instead of default TCP
```

### Docker image

It can be used as a container image, based in alpine:

```sh
docker run -it --privileged aojea/netkat:latest 192.168.68.1 80
2021/05/31 21:29:42 Using source address 172.17.0.2/16
2021/05/31 21:29:42 Creating raw socket
2021/05/31 21:29:42 Adding ebpf ingress filter on interface eth0
2021/05/31 21:29:42 filter {LinkIndex: 99, Handle: 0:1, Parent: ffff:fff2, Priority: 0, Protocol: 3}
2021/05/31 21:29:42 Creating user TCP/IP stack
2021/05/31 21:29:42 Dialing ...
2021/05/31 21:29:42 Connection established
```

## Development

netkat uses the [gvisor userspace TCP/IP stack "netstack"](https://pkg.go.dev/gvisor.dev/gvisor/pkg/tcpip)

It creates a RAW socket attached to the interface with the route to the destination IP,
attaching a BPF filter for the traffic mathing the connection parameters specified as
arguments.

It also creates an ingress queue and attaches an eBPF filter, to drop the traffic of
the connection directed to the RAW socket, preventing that the host stack drops the
connection.

