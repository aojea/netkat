package netkat

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

//go:generate $HOME/go/bin/bpf2go filter bpf/filter.c -- -I/usr/include -I./bpf -nostdinc -O3

const (
	nicID   = 1
	bufSize = 4 << 20 // 4MB.
)

var (
	flagListen    bool
	flagUDP       bool
	flagDebug     bool
	flagSrcPort   int
	flagInterface string
)

func init() {
	flag.BoolVar(&flagListen, "listen", false, "Bind and listen for incoming connections")
	flag.BoolVar(&flagUDP, "udp", false, "Use UDP instead of default TCP")
	flag.BoolVar(&flagDebug, "debug", false, "Debug")
	flag.IntVar(&flagSrcPort, "source-port", 0, "Specify source port to use")
	flag.StringVar(&flagInterface, "interface", "", "Specify interface to use. Default interface with default route")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: nk [options] [hostname] [port]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	var err error
	var destIP net.IP
	var sourceIP net.IP
	var destPort uint16

	// Check permissions
	cmd := exec.Command("id", "-u")
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	// 0 = root, 501 = non-root user
	i, err := strconv.Atoi(string(output[:len(output)-1]))
	if err != nil {
		log.Fatal(err)
	}
	if i != 0 {
		log.Fatal("This program must be run as root! (sudo)")
	}

	// Parse command line flags and arguments
	flag.Parse()
	args := flag.Args()

	// Validation
	if !flagListen {
		if len(args) != 2 {
			flag.Usage()
			os.Exit(1)
		}
		ips, err := net.LookupHost(args[0])
		if err != nil || len(ips) == 0 {
			log.Fatalf("Invalid destination Host: %s", args[0])
		}
		// use the first IP returned
		// TODO: revisit in case we want to specify the IP family
		destIP = net.ParseIP(ips[0])
		if destIP == nil {
			log.Fatalf("Invalid destination IP: %s", args[0])
		}
		i, err := strconv.Atoi(args[1])
		destPort = uint16(i)
		if err != nil || destPort == 0 {
			log.Fatalf("Invalid destination Port: %s", args[1])
		}
	} else {
		if flagSrcPort == 0 {
			log.Fatalf("Source port required in listening mode")
		}
	}

	// Defaulting

	// Use TCP by default
	transportProtocol := tcp.NewProtocol
	if flagUDP {
		transportProtocol = udp.NewProtocol
	}

	// Use IPv4 or IPv6 depending on the destination address
	isIPv6 := isIPv6Address(destIP)
	protocolNumber := ipv4.ProtocolNumber
	networkProtocol := ipv4.NewProtocol
	family := netlink.FAMILY_V4
	if isIPv6 {
		protocolNumber = ipv6.ProtocolNumber
		networkProtocol = ipv6.NewProtocol
		family = netlink.FAMILY_V6
	}

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer close(signalCh)
	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)
	go func() {
		<-signalCh
		log.Fatal("Exiting: received signal")
	}()

	// Detect interface name if needed
	intfName, gw, err := getDefaultGatewayInterfaceByFamily(family)
	if err != nil {
		log.Fatalf("Fail to get default interface: %v", err)
	}

	// override the interface if specified
	if flagInterface != "" {
		intfName = flagInterface
	}

	mtu, err := rawfile.GetMTU(intfName)
	if err != nil {
		log.Fatalf("Failed to get interface %s MTU: %v", intfName, err)
	}

	ifaceLink, err := netlink.LinkByName(intfName)
	if err != nil {
		log.Fatalf("unable to bind to %q: %v", "1", err)
	}

	// https: //github.com/google/gvisor/blob/108410638aa8480e82933870ba8279133f543d2b/test/benchmarks/tcp/tcp_proxy.go
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Could not create socket: %s", err.Error())
	}
	defer unix.Close(fd)

	if fd < 0 {
		log.Fatalf("Socket error: return < 0")
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		log.Fatalf("Error setting fd to nonblock: %s", err)
	}

	ll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceLink.Attrs().Index,
		Pkttype:  unix.PACKET_HOST,
	}

	if err := unix.Bind(fd, &ll); err != nil {
		log.Fatalf("unable to bind to %q: %v", "iface.Name", err)
	}

	prog, err := ebpf.NewProgram(
		&ebpf.ProgramSpec{
			Name:         "bpf_filter",
			Type:         ebpf.SocketFilter,
			Instructions: insns,
			License:      "GPL",
		},
	)
	if err != nil {
		log.Fatalf("Error creating eBPF program: %v", err)
	}
	defer prog.Close()

	bpfFd := prog.FD()
	err = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, bpfFd)
	if err != nil {
		log.Fatalf("unable to set BPF filter on socket: %v", err)
	}
	defer syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, bpfFd)

	// RAW Sockets by default have a very small SO_RCVBUF of 256KB,
	// up it to at least 4MB to reduce packet drops.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, bufSize); err != nil {
		log.Fatalf("setsockopt(..., SO_RCVBUF, %v,..) = %v", bufSize, err)
	}

	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, bufSize); err != nil {
		log.Fatalf("setsockopt(..., SO_SNDBUF, %v,..) = %v", bufSize, err)
	}

	// filter on the host so our userspace connections are not resetted
	// using tc since they are at the beginning of the pipeline
	// # add an ingress qdisc
	// tc qdisc add dev eth3 ingress
	// xref: https://codilime.com/pdf/codilime_packet_flow_in_netfilter_A3-1-1.pdf
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("Failed to add qdisc: %v", err)
	}
	defer func() {
		if err = netlink.QdiscDel(qdisc); err != nil {
			log.Fatalf("Failed to del qdisc: %v", err)
		}
	}()

	// https://man7.org/linux/man-pages/man8/tc-bpf.8.html
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           bpfFd,
		Name:         "nkFilter",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(ingressFilter); err != nil {
		log.Fatalf("Failed to add filter: %v", err)
	}
	defer netlink.FilterDel(ingressFilter)

	// add the socket to the userspace stack
	la := tcpip.LinkAddress(ifaceLink.Attrs().HardwareAddr)

	linkID, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: true,
		Address:        tcpip.LinkAddress(la),
		// Enable checksum generation as we need to generate valid
		// checksums for the veth device to deliver our packets to the
		// peer. But we do want to disable checksum verification as veth
		// devices do perform GRO and the linux host kernel may not
		// regenerate valid checksums after GRO.
		TXChecksumOffload:  false,
		RXChecksumOffload:  true,
		PacketDispatchMode: fdbased.RecvMMsg,
		ClosedFunc: func(e tcpip.Error) {
			if e != nil {
				log.Fatalf("File descriptor closed: %v", err)
			}
		},
	})

	if flagDebug {
		linkID = sniffer.New(linkID)
	}

	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{networkProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{transportProtocol},
	})
	defer func() {
		ipstack.Close()
		ipstack.Wait()
	}()
	// Add IPv4 and IPv6 default routes, so all traffic goes through the fake NIC
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	if isIPv6 {
		subnet, _ = tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
			Gateway:     ipToStackAddress(gw),
		},
	})

	if err := ipstack.CreateNIC(1, linkID); err != nil {
		log.Fatalf("Failed to create userspace NIC: %v", err)
	}

	// Take over the interface addresses
	addrs, err := netlink.AddrList(ifaceLink, netlink.FAMILY_ALL)
	if err != nil {
		log.Fatalf("Failed to list interface addresses: %v", err)
	}

	for _, a := range addrs {
		// Use global addresses only
		if !a.IP.IsGlobalUnicast() {
			continue
		}

		// use same IP family
		if isIPv6 != isIPv6Address(a.IP) {
			continue
		}

		// We only need one IP address
		// TODO: check how to handle multiple addresses
		log.Printf("Using source address %s", a.IPNet.String())
		sourceIP = a.IP
		break
	}

	if sourceIP == nil {
		log.Fatal("can't find a valid source address")
	}
	ipstack.AddAddress(nicID, protocolNumber, ipToStackAddress(sourceIP))
	// use the address as source
	laddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: ipToStackAddress(sourceIP),
		Port: uint16(flagSrcPort),
	}

	// Implement the netcat logic
	// It basically copies from stdin to a TCP/UDP socket in client mode
	// Or from a TCP/UDP socket to stdout in server mode

	// client mode: stdin ---> socket(hostname,port)
	if !flagListen {
		dest := tcpip.FullAddress{
			NIC:  nicID,
			Addr: ipToStackAddress(destIP),
			Port: destPort,
		}
		var conn net.Conn
		if !flagUDP {
			conn, err = dialTCP(ipstack, &laddr, &dest, protocolNumber)
			if err != nil {
				log.Fatalf("Can't connect to server: %s\n", err)
			}
		} else {
			conn, err = gonet.DialUDP(ipstack, &laddr, &dest, protocolNumber)
			if err != nil {
				log.Fatalf("Can't connect to server: %s\n", err)
			}
		}
		log.Printf("Connection established")
		_, err = io.Copy(conn, os.Stdin)
		if err != nil {
			log.Fatalf("Connection error: %s\n", err)
		}
		os.Exit(0)
	}

	// server mode: socket(localhost,port) ---> stdin
	if flagUDP {
		// TODO: UDP listeners
	} else {

	}
}

// getDefaultGatewayInterfaceByFamily return the default gw interface and IP
func getDefaultGatewayInterfaceByFamily(family int) (string, net.IP, error) {
	// filter the default route to obtain the gateway
	filter := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(family, filter, netlink.RT_FILTER_DST)
	if err != nil {
		return "", nil, errors.Wrapf(err, "failed to get routing table in node")
	}
	// use the first valid default gateway
	for _, r := range routes {
		// no multipath
		if len(r.MultiPath) == 0 {
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			if r.Gw == nil {
				continue
			}
			return intfLink.Attrs().Name, r.Gw, nil
		}

		// multipath, use the first valid entry
		// TODO: revisit for full multipath support
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			intfLink, err := netlink.LinkByIndex(nh.LinkIndex)
			if err != nil {
				continue
			}
			if nh.Gw == nil {
				continue
			}
			return intfLink.Attrs().Name, nh.Gw, nil
		}
	}
	return "", net.IP{}, fmt.Errorf("failed to get default gateway interface")
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func ipToStackAddress(ip net.IP) tcpip.Address {
	if ip.To4() != nil {
		return tcpip.Address(ip.To4())
	}
	return tcpip.Address(ip)
}

// dialTCP creates a new TCPConn connected to the specified address
// with the option of adding a source address and port.
func dialTCP(s *stack.Stack, laddr, raddr *tcpip.FullAddress, network tcpip.NetworkProtocolNumber) (*gonet.TCPConn, error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, network, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Bind so we can get a port and avoid the kernel RST the connection
	if laddr != nil {
		if err := ep.Bind(*laddr); err != nil {
			return nil, &net.OpError{
				Op:   "bind",
				Net:  "udp",
				Addr: fullToTCPAddr(*laddr),
				Err:  errors.New(err.String()),
			}
		}
	}

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.WritableEvents)
	defer wq.EventUnregister(&waitEntry)

	err = ep.Connect(*raddr)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		<-notifyCh
		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: fullToTCPAddr(*raddr),
			Err:  errors.New(err.String()),
		}
	}

	return gonet.NewTCPConn(&wq, ep), nil
}

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}

func isIPv6Address(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}
