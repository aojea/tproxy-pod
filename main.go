package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/coreos/go-iptables/iptables"
	"golang.org/x/sys/unix"
)

// Implement a transparent proxy that capture request to a specific range in a specific port
// and replies them with the IP of the destination port
// ref: https://docs.kernel.org/networking/tproxy.html

const (
	tproxyDivertChain = "TPROXY-DIVERT"
	iptablesMark      = "1"
)

var (
	flagPort int
	flagIPv6 bool
)

func init() {
	flag.IntVar(&flagPort, "p", 1, "port to listen")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: cloud-provider-kind [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	// Parse command line flags and arguments
	flag.Parse()

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

	// install iptables rules to divert traffic
	err := syncRules()
	if err != nil {
		log.Fatalf("Could not sync necessary iptables rules: %v", err)
	}

	// The webserver has to listen in a socket with  IP_TRANSPARENT
	log.Printf("Binding TCP TProxy listener to 0.0.0.0:%d", flagPort)
	// Create Listener Config
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT
				err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if err != nil {
					log.Fatalf("Could not set SO_REUSEADDR socket option: %s", err)
					return
				}
			})
		},
	}

	// Start Listener
	tcpListener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("0.0.0.0:%d", flagPort))
	if err != nil {
		log.Printf("Could not start TCP listener: %s", err)
		return
	}
	defer tcpListener.Close()

	//Create the default mux
	mux := http.NewServeMux()
	mux.HandleFunc("/", healthCheckHandler)

	//Create the server.
	s := &http.Server{
		Handler: mux,
	}

	go func() {
		defer cancel()
		err := s.Serve(tcpListener)
		if err != nil {
			log.Printf("Server exited with error %v", err)
		}
	}()

	select {
	case <-signalCh:
		log.Printf("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	log.Println("TProxy listener closing")
}

func healthCheckHandler(res http.ResponseWriter, req *http.Request) {
	log.Printf("Received request to %s : %+v\n", req.RequestURI, req)
	fmt.Fprintf(res, "Request received from %s destination %s : %v\n", req.Host, req.RequestURI, req)
}

// syncRules syncs the tproxy rules to divert traffic to our server
func syncRules() error {
	// Install iptables rule to divert traffic to our webserver
	protocol := iptables.ProtocolIPv4
	if flagIPv6 {
		protocol = iptables.ProtocolIPv6
	}
	ipt, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return err
	}

	// make sure our custom chain exists
	// iptables -t mangle -N DIVERT
	// iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
	// iptables -t mangle -A DIVERT -j MARK --set-mark 1
	// iptables -t mangle -A DIVERT -j ACCEPT
	exists, err := ipt.ChainExists("mangle", tproxyDivertChain)
	if err != nil {
		return fmt.Errorf("failed to list chains: %v", err)
	}
	if !exists {
		if err = ipt.NewChain("mangle", tproxyDivertChain); err != nil {
			return err
		}
	}
	if err := ipt.AppendUnique("mangle", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", tproxyDivertChain); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", tproxyDivertChain, "-j", "MARK", "--set-mark", "1"); err != nil {
		return err
	}
	if err := ipt.AppendUnique("mangle", tproxyDivertChain, "-j", "ACCEPT"); err != nil {
		return err
	}
	// # ip rule add fwmark 1 lookup 100
	// # ip route add local 0.0.0.0/0 dev lo table 100
	// TODO: make it idempotent, it creates new rules in each execution, create only if does not exist
	cmd := exec.Command("ip", "rule", "add", "fwmark", "1", "lookup", "100")
	if err := cmd.Run(); err != nil {
		return err
	}
	cmd = exec.Command("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
	if err := cmd.Run(); err != nil {
		// TODO it returns an error if route exists
		log.Printf("error trying to do AnyIP to the table 100: %v", err)
	}

	// iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 50080
	return ipt.InsertUnique("mangle", "PREROUTING", 1, "-p", "tcp", "-d", "10.244.0.0/16", "--dport", "8180", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-port", strconv.Itoa(flagPort))
}
