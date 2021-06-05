package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
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
)

// In listen mode, hostname and port control the address the server will bind to.
func listen(ctx context.Context, args []string) error {
	var err error
	var localIP net.IP
	var localPort uint16

	// Validation
	// In listen mode, hostname and port control the address the server will bind to.
	localIP = net.ParseIP(args[0])
	if localIP == nil {
		return fmt.Errorf("Invalid hostname %s", args[0])
	}

	intfName, err := getInterfaceFromIP(localIP)
	if err != nil {
		return errors.Wrapf(err, "Invalid local IP: %s", args[0])
	}

	// override the interface if specified
	if flagInterface != "" {
		intfName = flagInterface
	}

	i, err := strconv.Atoi(args[1])
	localPort = uint16(i)
	if err != nil || localPort == 0 {
		return fmt.Errorf("Invalid local Port: %s", args[1])
	}
	if flagSrcPort != 0 {
		return fmt.Errorf("Source port flag only available in connect mode: %d", flagSrcPort)
	}

	// Defaulting

	// Use TCP by default
	transportProtocol := tcp.NewProtocol
	transportProtocolNumber := tcp.ProtocolNumber
	if flagUDP {
		transportProtocol = udp.NewProtocol
		transportProtocolNumber = udp.ProtocolNumber
	}

	// Use IPv4 or IPv6 depending on the destination address
	isIPv6 := isIPv6Address(localIP)
	protocolNumber := ipv4.ProtocolNumber
	networkProtocol := ipv4.NewProtocol
	family := netlink.FAMILY_V4
	if isIPv6 {
		protocolNumber = ipv6.ProtocolNumber
		networkProtocol = ipv6.NewProtocol
		family = netlink.FAMILY_V6
	}

	mtu, err := rawfile.GetMTU(intfName)
	if err != nil {
		return fmt.Errorf("Failed to get interface %s MTU: %v", intfName, err)
	}

	ifaceLink, err := netlink.LinkByName(intfName)
	if err != nil {
		return fmt.Errorf("unable to bind to %q: %v", intfName, err)
	}

	log.Printf("Creating raw socket")
	// https://github.com/google/gvisor/blob/108410638aa8480e82933870ba8279133f543d2b/test/benchmarks/tcp/tcp_proxy.go
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("Could not create socket: %s", err.Error())
	}
	defer unix.Close(fd)

	if fd < 0 {
		return fmt.Errorf("Socket error: return < 0")
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return fmt.Errorf("Error setting fd to nonblock: %s", err)
	}

	ll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifaceLink.Attrs().Index,
		Pkttype:  unix.PACKET_HOST,
	}

	if err := unix.Bind(fd, &ll); err != nil {
		return fmt.Errorf("unable to bind to %q: %v", "iface.Name", err)
	}

	// Add a filter to the socket so we receive only the packets we are interested
	// TODO we can make this more restrictive with source IP and source Port
	// xref: https://blog.cloudflare.com/bpf-the-forgotten-bytecode/

	// offset 23 protocol 6 TCP 17 UDP
	bpfProto := uint32(6)
	if flagUDP {
		bpfProto = uint32(17)
	}
	bpfFilter := []bpf.Instruction{
		// check the ethertype
		bpf.LoadAbsolute{Off: 12, Size: 2},
		// allow arp
		bpf.JumpIf{Val: 0x0806, SkipTrue: 10},
		// check is ipv4
		bpf.JumpIf{Val: 0x0800, SkipFalse: 10},
		// check the protocol
		bpf.LoadAbsolute{Off: 23, Size: 1},
		bpf.JumpIf{Val: bpfProto, SkipFalse: 8},
		// check the destination address
		bpf.LoadAbsolute{Off: 30, Size: 4},
		bpf.JumpIf{Val: binary.BigEndian.Uint32(localIP.To4()), SkipFalse: 6},
		// skip if offset non zero
		bpf.LoadAbsolute{Off: 20, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipTrue: 4},
		// check the destination port
		bpf.LoadMemShift{Off: 14},
		bpf.LoadIndirect{Off: 16, Size: 2},
		bpf.JumpIf{Val: uint32(localPort), SkipFalse: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0x0},
	}

	if isIPv6 {
		bpfFilter = []bpf.Instruction{
			// check the ethertype
			bpf.LoadAbsolute{Off: 12, Size: 2},
			bpf.JumpIf{Val: 0x86dd, SkipFalse: 14},
			// check the protocol
			bpf.LoadAbsolute{Off: 20, Size: 1},
			// allow icmpv6
			bpf.JumpIf{Val: 58, SkipTrue: 11},
			bpf.JumpIf{Val: bpfProto, SkipFalse: 11},
			// check the destination address
			bpf.LoadAbsolute{Off: 38, Size: 4},
			bpf.JumpIf{Val: binary.BigEndian.Uint32(localIP.To16()[0:4]), SkipFalse: 9},
			bpf.LoadAbsolute{Off: 42, Size: 4},
			bpf.JumpIf{Val: binary.BigEndian.Uint32(localIP.To16()[4:8]), SkipFalse: 7},
			bpf.LoadAbsolute{Off: 46, Size: 4},
			bpf.JumpIf{Val: binary.BigEndian.Uint32(localIP.To16()[8:12]), SkipFalse: 5},
			bpf.LoadAbsolute{Off: 50, Size: 4},
			bpf.JumpIf{Val: binary.BigEndian.Uint32(localIP.To16()[12:16]), SkipFalse: 3},
			// check the destination port
			bpf.LoadAbsolute{Off: 56, Size: 2},
			bpf.JumpIf{Val: uint32(localPort), SkipFalse: 1},
			bpf.RetConstant{Val: 0xffff}, // accept
			bpf.RetConstant{Val: 0x0},    // drop
		}
	}
	filter, err := bpf.Assemble(bpfFilter)
	if err != nil {
		return fmt.Errorf("Failed to generate BPF assembler: %v", err)
	}

	f := make([]unix.SockFilter, len(filter))
	for i := range filter {
		f[i].Code = filter[i].Op
		f[i].Jf = filter[i].Jf
		f[i].Jt = filter[i].Jt
		f[i].K = filter[i].K
	}
	fprog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &f[0],
	}
	err = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
	if err != nil {
		return fmt.Errorf("unable to set BPF filter on socket: %v", err)
	}

	log.Printf("Adding ebpf ingress filter on interface %s", ifaceLink.Attrs().Name)
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
		return fmt.Errorf("Failed to add qdisc: %v", err)
	}
	defer netlink.QdiscDel(qdisc)

	spec, err := loadFilter()
	if err != nil {
		return fmt.Errorf("Error creating eBPF program: %v", err)
	}

	// TODO: IPv6
	err = spec.RewriteConstants(map[string]interface{}{
		"PROTO":     uint8(transportProtocolNumber),
		"IP_FAMILY": uint8(family),
		// "SRC_IP":    0,
		"DST_IP": ip2int(localIP),
		// "SRC_PORT":  0,
		"DST_PORT": uint16(localPort),
	})
	if err != nil {
		return fmt.Errorf("Error rewriting eBPF program: %v", err)
	}

	objs := filterObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("failed to load objects: %v", err)
	}
	defer objs.Close()

	bpfFd := objs.Ingress.FD()
	// https://man7.org/linux/man-pages/man8/tc-bpf.8.html
	ingressFilter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifaceLink.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, 1),
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           bpfFd,
		Name:         "nkFilter",
		DirectAction: true,
	}

	log.Printf("filter %v", ingressFilter.String())
	if err := netlink.FilterAdd(ingressFilter); err != nil {
		return fmt.Errorf("Failed to add filter: %v", err)
	}
	defer netlink.FilterDel(ingressFilter)

	log.Printf("Creating user TCP/IP stack")
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
	})
	if err != nil {
		return fmt.Errorf("Can't create user-space link: %v\n", err)
	}

	if flagDebug {
		linkID = sniffer.New(linkID)
	}

	ipstack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{networkProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{transportProtocol},
	})
	defer func() {
		ipstack.Close()
	}()

	if err := ipstack.CreateNIC(1, linkID); err != nil {
		return fmt.Errorf("Failed to create userspace NIC: %v", err)
	}

	ipstack.AddAddress(nicID, protocolNumber, ipToStackAddress(localIP))
	// use the address as source
	laddr := tcpip.FullAddress{
		NIC:  nicID,
		Addr: ipToStackAddress(localIP),
		Port: uint16(localPort),
	}

	// Add IPv4 and IPv6 default routes, so all traffic goes through the fake NIC
	subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	if isIPv6 {
		subnet, _ = tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: subnet,
			NIC:         nicID,
		},
	})

	// Implement the netcat logic
	// It basically copies from a TCP/UDP socket to stdout in server mode

	// server mode: socket(localhost,port) ---> stdin
	if flagUDP {
		// TODO: UDP listeners
	} else {
		l, err := gonet.ListenTCP(ipstack, laddr, protocolNumber)
		if err != nil {
			return fmt.Errorf("Error open TCP listener: %v", err)
		}
		defer l.Close()
		log.Printf("Listening on %s:%d", localIP, localPort)
		// accept connections
		errCh := make(chan error, 2)
		go func() {
			inConn, err := l.Accept()
			if err != nil {
				errCh <- err
				return
			}
			log.Printf("incoming connection established.")
			defer inConn.Close()

			// process connection
			go func() {
				_, err = io.Copy(inConn, os.Stdin)
				errCh <- err
			}()
			_, err = io.Copy(os.Stdout, inConn)
			errCh <- err

		}()
		// the signal handler can unblock this too
		select {
		case err = <-errCh:
			log.Printf("Connection error: %v", err)
		case <-ctx.Done():
			log.Printf("Done")
		}

		// give a chance to terminate gracefully
		time.Sleep(500 * time.Millisecond)
	}
	return err
}
