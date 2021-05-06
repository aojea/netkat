package main

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

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/link/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	nicID = 1
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

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer close(signalCh)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGINT)
	go func() {
		<-signalCh
		log.Fatal("Exiting: received signal")
	}()

	// Detect interface name if needed
	intfName := flagInterface
	if intfName == "" {
		intfName, err = getDefaultRouteInterface()
		if err != nil {
			log.Fatal(err)
		}
	}

	mtu, err := rawfile.GetMTU(intfName)
	if err != nil {
		log.Fatal(err)
	}

	ifaceLink, err := netlink.LinkByName(intfName)
	if err != nil {
		log.Fatalf("unable to bind to %q: %v", "1", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		log.Fatalf("Could not create socket: %s", err.Error())
	}
	defer syscall.Close(fd)

	if fd < 0 {
		log.Fatalf("Socket error: return < 0")
	}

	if err = syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		log.Fatalf("Error setting fd to nonblock: %s", err)
	}

	ll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifaceLink.Attrs().Index,
		Hatype:   0, // No ARP type.
		Pkttype:  syscall.PACKET_HOST,
	}

	if err := syscall.Bind(fd, &ll); err != nil {
		log.Fatalf("unable to bind to %q: %v", "iface.Name", err)
	}

	la := tcpip.LinkAddress(ifaceLink.Attrs().HardwareAddr)

	linkID, err := fdbased.New(&fdbased.Options{
		FDs:            []int{fd},
		MTU:            mtu,
		EthernetHeader: true,
		Address:        la,
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
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{transportProtocol},
	})

	// Add IPv4 and IPv6 default routes, so all traffic goes through the fake NIC
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         nicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         nicID,
		},
	})

	if err := ipstack.CreateNIC(1, linkID); err != nil {
		log.Fatal(err)
	}

	// Take over the interface addresses
	addrs, err := netlink.AddrList(ifaceLink, netlink.FAMILY_ALL)
	if err != nil {
		log.Fatal(err)
	}
	for _, a := range addrs {
		// Use global addresses only
		if !a.IP.IsGlobalUnicast() {
			continue
		}
		ipstack.AddAddress(nicID, getProtocolNumber(a.IP), ipToStackAddress(a.IP))
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
			conn, err = gonet.DialTCP(ipstack, dest, getProtocolNumber(destIP))
			if err != nil {
				log.Fatalf("Can't connect to server: %s\n", err)
			}
		} else {
			conn, err = gonet.DialUDP(ipstack, nil, &dest, getProtocolNumber(destIP))
			if err != nil {
				log.Fatalf("Can't connect to server: %s\n", err)
			}
		}
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

// getDefaultRouteInterface return the interface name used by the default route
func getDefaultRouteInterface() (string, error) {
	// filter the default route to obtain the gateway
	filter := &netlink.Route{Dst: nil}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_DST)
	if err != nil {
		return "", errors.Wrapf(err, "failed to get routing table in node")
	}
	// use the first valid default gateway
	for _, r := range routes {
		// no multipath
		if len(r.MultiPath) == 0 {
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", r, err)
				continue
			}
			if r.Gw == nil {
				log.Printf("Failed to get gateway for route %v : %v", r, err)
				continue
			}
			log.Printf("Found default gateway interface %s %s", intfLink.Attrs().Name, r.Gw.String())
			return intfLink.Attrs().Name, nil
		}

		// multipath, use the first valid entry
		// TODO: revisit for full multipath support
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			intfLink, err := netlink.LinkByIndex(nh.LinkIndex)
			if err != nil {
				log.Printf("Failed to get interface link for route %v : %v", nh, err)
				continue
			}
			if nh.Gw == nil {
				log.Printf("Failed to get gateway for multipath route %v : %v", nh, err)
				continue
			}
			log.Printf("Found default gateway interface %s %s", intfLink.Attrs().Name, nh.Gw.String())
			return intfLink.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("failed to get default gateway interface")
}

// htons converts a short (uint16) from host-to-network byte order.
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func getProtocolNumber(ip net.IP) tcpip.NetworkProtocolNumber {
	if ip.To4() != nil {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func ipToStackAddress(ip net.IP) tcpip.Address {
	if ip.To4() != nil {
		return tcpip.Address(ip.To4())
	}
	return tcpip.Address(ip)
}
