package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"gvisor.dev/gvisor/pkg/tcpip"
)

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

func fullToTCPAddr(addr tcpip.FullAddress) *net.TCPAddr {
	return &net.TCPAddr{IP: net.IP(addr.Addr), Port: int(addr.Port)}
}

func isIPv6Address(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// newIPNet generates an IPNet from an ip address using a netmask of 32 or 128.
func newIPNet(ip net.IP) *net.IPNet {
	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func getInterfaceFromIP(localIP net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if localIP.Equal(ip) {
				return i.Name, nil
			}
		}
	}
	return "", fmt.Errorf("%s IP not found in the host", localIP.String())
}

// getConnectionDetails return the output interface, the source IP used
// and the IP address of the gateway
func getConnectionDetails(dst net.IP) (string, net.IP, net.IP, error) {
	routes, err := netlink.RouteGet(dst)
	if err != nil {
		return "", nil, nil, errors.Wrapf(err, "failed to get routing table in node")
	}
	// use the first valid route
	for _, r := range routes {
		log.Println("routes", r)
		// no multipath
		if len(r.MultiPath) == 0 {
			intfLink, err := netlink.LinkByIndex(r.LinkIndex)
			if err != nil {
				continue
			}
			return intfLink.Attrs().Name, r.Gw, r.Src, nil
		}

		// multipath, use the first valid entry
		// TODO: revisit for full multipath support
		// xref: https://github.com/vishvananda/netlink/blob/6ffafa9fc19b848776f4fd608c4ad09509aaacb4/route.go#L137-L145
		for _, nh := range r.MultiPath {
			intfLink, err := netlink.LinkByIndex(nh.LinkIndex)
			if err != nil {
				continue
			}
			return intfLink.Attrs().Name, nh.Gw, r.Src, nil
		}
	}
	return "", net.IP{}, net.IP{}, fmt.Errorf("failed to get default gateway interface")
}
