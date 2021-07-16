package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/unix"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

//go:generate bpf2go filter bpf/filter.c -- -I/usr/include -I./bpf -nostdinc -O3

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
	flagWait      int
)

func init() {
	flag.BoolVar(&flagListen, "listen", false, "Bind and listen for incoming connections")
	flag.BoolVar(&flagListen, "l", false, "Bind and listen for incoming connections")
	flag.BoolVar(&flagUDP, "udp", false, "Use UDP instead of default TCP")
	flag.BoolVar(&flagUDP, "u", false, "Use UDP instead of default TCP")
	flag.BoolVar(&flagDebug, "debug", false, "Debug")
	flag.BoolVar(&flagDebug, "d", false, "Debug")
	flag.IntVar(&flagSrcPort, "source-port", 0, "Specify source port to use on connections")
	flag.IntVar(&flagSrcPort, "p", 0, "Specify source port to use on connections")
	flag.StringVar(&flagInterface, "interface", "", "Specify interface to use. Default interface with default route")
	flag.StringVar(&flagInterface, "i", "", "Specify interface to use. Default interface with default route")
	flag.IntVar(&flagWait, "wait", 5, "Connect timeout")
	flag.IntVar(&flagWait, "w", 5, "Connect timeout")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: nk [options] [hostname] [port]\n\n"+
			"In connect mode, the hostname and port arguments tell what to connect.\n"+
			"In listen mode, hostname and port control the address the server will bind to.\n\n")
		flag.PrintDefaults()
	}
}

func main() {

	// Check system requirements

	// Kernel must be > 5.2
	k, m, err := getKernelVersion()
	if err != nil {
		log.Fatal(err)
	}
	if k < 5 || k == 5 && m < 2 {
		log.Fatalf("Host Kernel (%d.%d) does not meet minimum required version: (%d.%d)",
			k, m, 5, 2)
	}

	c := cap.GetProc()
	if on, _ := c.GetFlag(cap.Permitted, cap.NET_RAW); !on {
		log.Fatalf("insufficient privilege to open RAW sockets - want %q, have %q", cap.NET_RAW, c)
	}

	if on, _ := c.GetFlag(cap.Permitted, cap.SYS_RESOURCE); !on {
		log.Fatalf("insufficient privilege to set rlimit - want %q, have %q", cap.SYS_RESOURCE, c)
	}

	// Parse command line flags and arguments
	flag.Parse()
	args := flag.Args()

	// trap Ctrl+C and call cancel on the context
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	// Enable signal handler
	signalCh := make(chan os.Signal, 2)
	defer func() {
		close(signalCh)
		cancel()
	}()

	signal.Notify(signalCh, os.Interrupt, unix.SIGINT)
	go func() {
		select {
		case <-signalCh:
			log.Printf("Exiting: received signal")
			cancel()
		case <-ctx.Done():
		}
	}()

	if len(args) != 2 {
		flag.Usage()
		os.Exit(1)
	}

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("setting temporary rlimit: %s", err)
	}

	if !flagListen {
		err = connect(ctx, args)
		if err != nil {
			log.Fatalln(err)
		}
	} else {
		err = listen(ctx, args)
		if err != nil {
			log.Fatalln(err)
		}
	}
	os.Exit(0)

}

func getKernelVersion() (kernel, major int, err error) {
	uts := unix.Utsname{}
	if err = unix.Uname(&uts); err != nil {
		return
	}

	ba := make([]byte, 0, len(uts.Release))
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		ba = append(ba, byte(b))
	}
	var rest string
	if n, _ := fmt.Sscanf(string(ba), "%d.%d%s", &kernel, &major, &rest); n < 2 {
		err = fmt.Errorf("can't parse kernel version in %q", string(ba))
	}
	return
}
