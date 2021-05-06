package main

import (
	"flag"
	"fmt"
	"os"
)

const (
	mtu   = 1500
	nicID = 1
)

var (
	flagListen  bool
	flagUDP     bool
	flagSrcPort int
)

func init() {
	flag.BoolVar(&flagListen, "listen", false, "Bind and listen for incoming connections")
	flag.BoolVar(&flagUDP, "udp", false, "Use UDP instead of default TCP")
	flag.IntVar(&flagSrcPort, "source-port", 0, "Specify source port to use")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: nk [options] [hostname] [port]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}
}
