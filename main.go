package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/knftables"
)

// Implement a TLS transparent proxy
// It listen in a TCP port expecting and forwards it to the destination address of the socket
// ref: https://docs.kernel.org/networking/tproxy.html

const (
	rfc1918Set         = "private-cidrs-set"
	rfc1918CIDRs       = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
	nftTable           = "tls-pod-sidecar"
	tproxyTable        = 10
	tproxyMarkTCPtoTLS = 10
	tproxyMarkTLStoTCP = 11
	tproxyBypassMark   = 12
)

var (
	flagPortTCP         int
	flagPortTLS         int
	flagIPv6            bool
	flagRootCertificate string
	flagCertificate     string
	flagKey             string
	tlsConfig           *tls.Config
)

var bypassDialer = &net.Dialer{
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			// Mark connections so thet are not processed by the netfilter TPROXY rules
			if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tproxyBypassMark); err != nil {
				klog.Fatalf("setting SO_MARK bypass: %v", err)
				return
			}
		})
	},
}

func init() {
	flag.IntVar(&flagPortTCP, "tcp-port", 1, "port to listen on TCP")
	flag.IntVar(&flagPortTLS, "tls-port", 2, "port to listen on TLS")
	flag.StringVar(&flagRootCertificate, "ca-cert", "", "root certificate")
	flag.StringVar(&flagCertificate, "cert", "", "certificate")
	flag.StringVar(&flagKey, "key", "", "certificate key")

	flag.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: tls-tproxy [options]\n\n")
		flag.PrintDefaults()
	}
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	klog.Infof("flags: %v", flag.Args())

	var cert tls.Certificate
	var err error
	if flagCertificate == "" || flagKey == "" {
		cert, err = tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			klog.Fatalf("Failed to build cert with error: %+v", err)
		}
	} else {
		cert, err = tls.LoadX509KeyPair(flagCertificate, flagKey)
		if err != nil {
			klog.Fatal(err)
		}
	}

	tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}

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
	err = syncRules()
	if err != nil {
		log.Fatalf("Could not sync necessary iptables rules: %v", err)
	}

	err = syncRoutes()
	if err != nil {
		log.Fatalf("Could not sync tproxy routing rules: %v", err)
	}

	// The TCP socket has to listen in a socket with IP_TRANSPARENT
	klog.Infof("Binding TCP TProxy listener to 127.0.0.1:%d", flagPortTCP)
	// Create Listener Config
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT
				err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if err != nil {
					log.Fatalf("Could not set IP_TRANSPARENT socket option: %s", err)
					return
				}
			})
		},
	}

	// Start Listener
	tcpListener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", flagPortTCP))
	if err != nil {
		klog.Infof("Could not start TCP listener: %s", err)
		return
	}
	defer tcpListener.Close()

	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					klog.Infof("Temporary error while accepting connection: %s", netErr)
				}

				log.Fatalf("Unrecoverable error while accepting connection: %s", err)
				return
			}

			go handleTCPConn(conn)
		}
	}()

	// The TCP socket has to listen in a socket with IP_TRANSPARENT
	klog.Infof("Binding TLS TProxy listener to 127.0.0.1:%d", flagPortTLS)
	// Create Listener Config
	lcTLS := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT
				err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if err != nil {
					log.Fatalf("Could not set IP_TRANSPARENT socket option: %s", err)
					return
				}
				// Mark connections so thet are not processed by the netfilter TPROXY rules
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tproxyBypassMark); err != nil {
					klog.Fatalf("setting SO_MARK bypass: %v", err)
					return
				}
			})
		},
	}
	// Start Listener
	tcpTLSListener, err := lcTLS.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", flagPortTLS))
	if err != nil {
		klog.Infof("Could not start TCP listener: %s", err)
		return
	}
	defer tcpTLSListener.Close()

	caCertPool := x509.NewCertPool()
	var caCertFile []byte
	if flagRootCertificate != "" {
		caCertFile, err = os.ReadFile(flagRootCertificate)
		if err != nil {
			klog.Fatalf("failed to load root certificate: %v", err)
		}
	} else {
		caCertFile = localhostCert
	}

	caCertPool.AppendCertsFromPEM(caCertFile)
	tlsServerConfig := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	tlsListener := tls.NewListener(tcpTLSListener, tlsServerConfig)

	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
					klog.Infof("Temporary error while accepting connection: %s", netErr)
				}

				log.Fatalf("Unrecoverable error while accepting connection: %s", err)
				return
			}

			go handleTLSConn(conn)
		}
	}()

	select {
	case <-signalCh:
		klog.Infof("Exiting: received signal")
		cancel()
	case <-ctx.Done():
	}

	log.Println("TProxy listener closing")
}

func handleTCPConn(conn net.Conn) {
	klog.Infof("Accepting TCP connection from %s with destination of %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	defer conn.Close()

	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		klog.Infof("Failed to get remote address [%s]: %v", conn.LocalAddr().String(), err)
		return
	}

	klog.Infof("Connecting to [%s]", net.JoinHostPort(host, port))

	remoteConn, err := tls.DialWithDialer(bypassDialer, "tcp", net.JoinHostPort(host, port), tlsConfig)
	if err != nil {
		klog.Infof("Failed to connect to original destination [%s]: %s", conn.LocalAddr().String(), err)
		return
	}
	defer remoteConn.Close()

	var streamWait sync.WaitGroup
	streamWait.Add(2)

	streamConn := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		streamWait.Done()
	}

	go streamConn(remoteConn, conn)
	go streamConn(conn, remoteConn)

	streamWait.Wait()
}

func handleTLSConn(conn net.Conn) {
	klog.Infof("Accepting TLS connection from %s with destination of %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	defer conn.Close()

	if _, ok := conn.(*tls.Conn); !ok {
		klog.Infof("not a TLS connection")
		return
	}

	err := conn.(*tls.Conn).Handshake()
	if err != nil {
		klog.Infof("Handshak error: %v", err)
		return
	}

	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		klog.Infof("Failed to get local address [%s]: %v", conn.LocalAddr().String(), err)
		return
	}
	// connect on the localhost address
	host = "127.0.0.1"
	klog.Infof("Connecting to [%s]", net.JoinHostPort(host, port))

	/* disable because it may break conntrack
	remoteHost, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		klog.Infof("Failed to get remote address [%s]: %v", conn.RemoteAddr().String(), err)
		return
	}
	rPort, err := strconv.Atoi(remotePort)
	if err != nil {
		klog.Infof("Failed to get remote port [%s]: %v", remotePort, err)
		return
	}

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP(remoteHost),
			//		Port: rPort,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Enable IP_TRANSPARENT to be able to use the remote host IP as source
				err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
				if err != nil {
					klog.Fatalf("Could not set IP_TRANSPARENT socket option: %v", err)
					return
				}
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tproxyBypassMark); err != nil {
					klog.Fatalf("setting SO_MARK bypass: %v", err)
					return
				}
			})
		},
	}
	*/

	remoteConn, err := net.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		klog.Infof("Failed to connect to original destination [%s]: %s", conn.LocalAddr().String(), err)
		return
	}
	defer remoteConn.Close()

	var streamWait sync.WaitGroup
	streamWait.Add(2)

	streamConn := func(dst io.Writer, src io.Reader) {
		io.Copy(dst, src)
		streamWait.Done()
	}

	go streamConn(remoteConn, conn)
	go streamConn(conn, remoteConn)

	streamWait.Wait()
}

// syncRules syncs the tproxy rules to divert traffic to our server
func syncRules() error {
	// Install nftables rule to divert traffic to our proxies
	klog.V(2).Info("Initializing nftables")
	nft, err := knftables.New(knftables.InetFamily, nftTable)
	if err != nil {
		return err
	}
	table := &knftables.Table{
		Comment: knftables.PtrTo("rules for sidecar mTLS proxy"),
	}
	tx := nft.NewTransaction()
	// do it once to delete the existing table
	tx.Add(table)
	tx.Delete(table)
	tx.Add(table)

	// add set with IP CIDRs that should be proxied.
	// TODO: use Pod, Node and Service CIDRs
	tx.Add(&knftables.Set{
		Name:    rfc1918Set,
		Type:    "ipv4_addr",
		Flags:   []knftables.SetFlag{knftables.IntervalFlag},
		Comment: ptr.To("RFC1919 CIDRs"),
	})
	tx.Flush(&knftables.Set{
		Name: rfc1918Set,
	})
	for _, cdir := range strings.Split(rfc1918CIDRs, ",") {
		tx.Add(&knftables.Element{
			Set: rfc1918Set,
			Key: []string{cdir},
		})
	}

	// Add a chain on the PREROUTING HOOK
	preroutingChain := string("tproxy-prerouting")
	tx.Add(&knftables.Chain{
		Name:     preroutingChain,
		Type:     knftables.PtrTo(knftables.FilterType),
		Hook:     knftables.PtrTo(knftables.PreroutingHook),
		Priority: knftables.PtrTo(knftables.ManglePriority + "-5"),
	})
	tx.Flush(&knftables.Chain{
		Name: preroutingChain,
	})
	tx.Add(&knftables.Rule{
		Chain: preroutingChain,
		Rule: knftables.Concat(
			"ip", "daddr", "!=", "@", rfc1918Set, "return",
		),
		Comment: ptr.To("not process traffic not in cluster"),
	})
	// process coming from external interface
	// https://www.netfilter.org/projects/nftables/manpage.html
	// incoming traffic from outside should be redirected to the TLS listener
	tx.Add(&knftables.Rule{
		Chain: preroutingChain,
		Rule: knftables.Concat(
			"meta", "iifname", "!=", "lo", "meta", "l4proto", "tcp", "tproxy", "ip", "to", net.JoinHostPort("127.0.0.1", strconv.Itoa(flagPortTLS)), "accept",
		),
		Comment: ptr.To("external originated traffic to TLS proxy"),
	})

	// Packet originated internally (not by this proxy) should be redirected
	// to the TCP listener that will create a new TLS connection to the original
	// destination and proxy it
	// https://docs.kernel.org/networking/tproxy.html
	// https://manpages.debian.org/bullseye/nftables/nft.8#SOCKET_EXPRESSIO
	// nft add rule filter divert tcp dport 80 tproxy to :50080 meta mark set 1 accept
	tx.Add(&knftables.Rule{
		Chain: preroutingChain,
		Rule: knftables.Concat(
			"meta", "mark", tproxyMarkTCPtoTLS, "meta", "l4proto", "tcp", "tproxy", "ip", "to", net.JoinHostPort("127.0.0.1", strconv.Itoa(flagPortTCP)), "accept",
		),
		Comment: ptr.To("local originated traffic to TCP proxy"),
	})

	// Add a chain on the OUTPUT HOOK
	// packets generated in the namespace
	outputChain := string("tproxy-output")
	tx.Add(&knftables.Chain{
		Name:     outputChain,
		Type:     knftables.PtrTo(knftables.RouteType),
		Hook:     knftables.PtrTo(knftables.OutputHook),
		Priority: knftables.PtrTo(knftables.SNATPriority + "-5"),
	})
	tx.Flush(&knftables.Chain{
		Name: outputChain,
	})
	// bypass mark
	tx.Add(&knftables.Rule{
		Chain: outputChain,
		Rule: knftables.Concat(
			"meta", "mark", tproxyBypassMark, "return",
		),
	})
	tx.Add(&knftables.Rule{
		Chain: outputChain,
		Rule: knftables.Concat(
			"ip", "daddr", "!=", "@", rfc1918Set, "return",
		),
		Comment: ptr.To("not process traffic not in cluster"),
	})
	// Mark traffic originated locally and destined to an external address to be processed by the transparent proxy
	tx.Add(&knftables.Rule{
		Chain: outputChain,
		Rule: knftables.Concat(
			"meta", "oifname", "!=", "lo", "meta", "l4proto", "tcp", "meta", "mark", "set", tproxyMarkTCPtoTLS,
		),
	})

	if err := nft.Run(context.TODO(), tx); err != nil {
		klog.Infof("error syncing nftables rules %v", err)
		return err
	}
	return nil

}

// https://github.com/istio/istio/blob/c3ab6023f2867716455dfc1e1bde7e34845b0f44/tools/istio-iptables/pkg/capture/run_linux.go#L29C1-L87C2
func syncRoutes() error {
	link, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to find 'lo' link: %v", err)
	}

	r := netlink.NewRule()
	r.Family = unix.AF_INET // TODO IPv6
	r.Table = tproxyTable
	r.Mark = tproxyMarkTCPtoTLS
	// If the interface is loopback, the rule only matches packets originating from this host.
	// https://man7.org/linux/man-pages/man8/ip-rule.8.html
	r.IifName = "lo"
	if err := netlink.RuleAdd(r); err != nil {
		return fmt.Errorf("failed to configure netlink rule: %v", err)
	}

	// Send all routes that need to be transparently proxied through the lo interface
	// so it picks the rule in the PREROUTING table to redirect to the proxy
	// Equivalent to `ip route add local default dev lo table <table>`
	cidrs := []string{"0.0.0.0/0"}
	for _, fullCIDR := range cidrs {
		_, dst, err := net.ParseCIDR(fullCIDR)
		if err != nil {
			return fmt.Errorf("parse CIDR: %v", err)
		}

		err = netlink.RouteAdd(&netlink.Route{
			Dst:       dst,
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
			Table:     tproxyTable,
			LinkIndex: link.Attrs().Index,
		})
		if err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "file exists") {
				return fmt.Errorf("failed to add route: %v", err)
			}

		}
	}
	return nil
}

// localhostCert was generated from crypto/tls/generate_cert.go with the following command:
//
//	go run generate_cert.go  --rsa-bits 2048 --host 127.0.0.1,::1,example.com,webhook.test.svc --ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`-----BEGIN CERTIFICATE-----
MIIDTDCCAjSgAwIBAgIRAJXp/H5o/ItwCEK9emP3NiMwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAOCyQ/2e9SVZ3QSW1yxe9OoZeyX7N8jRRyRkWlSL/OiEIxGsDJHK
GcDrGONOm9FeKM73evSiNX+7AZEqdanT37RsvVHTbRKAKsNIilyFTYmSvPHC05iG
agcIBm/Wt+NvfNb3DFLPhCLZbeuqlKhMzc8NeWHNY6eJj1qqks70PNlcb3Q5Ufa2
ttxs3N4pUmi7/ntiFE+X42A6IGX94Zyu9E7kH+0/ajvEA0qAyIXp1TneMgybS+ox
UBLDBQvsOH5lwvVIUfJLI483geXbFaUpHc6fTKE/8/f6EuWWEN3UFvuDM6cqr51e
MPTziUVUs5NBIeHIGyTKTbF3+gTXFKDf/jECAwEAAaOBmjCBlzAOBgNVHQ8BAf8E
BAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zAdBgNV
HQ4EFgQURFTsa1/pfERE/WJ3YpkbnKI6NkEwQAYDVR0RBDkwN4ILZXhhbXBsZS5j
b22CEHdlYmhvb2sudGVzdC5zdmOHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJ
KoZIhvcNAQELBQADggEBAE60cASylHw0DsHtTkQwjhmW0Bd1Dy0+BvGngD9P85tB
fNHtcurzGG1GSGVX7ClxghDZo84WcV742qenxBlZ37WTqmD5/4pWlEvbrjKmgr3W
yWM6WJts1W4T5aR6mU2jHz1mxIFq9Fcw2XcdtwHAJKoCKpLv6pYswW4LYODdKNii
eAKBEcbEBQ3oU4529yeDpkU6ZLBKH+ZVxWI3ZUWbpv5O6vMtSB9nvtTripbWrm1t
vpCEETNAOP2hbLnPwBXUEN8KBs94UdufOFIhArNgKonY/oZoZnZYWVyRtkex+b+r
MarmcIKMrgoYweSQiCa+XVWofz2ZSOvzxta6Y9iDI74=
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDgskP9nvUlWd0E
ltcsXvTqGXsl+zfI0UckZFpUi/zohCMRrAyRyhnA6xjjTpvRXijO93r0ojV/uwGR
KnWp09+0bL1R020SgCrDSIpchU2JkrzxwtOYhmoHCAZv1rfjb3zW9wxSz4Qi2W3r
qpSoTM3PDXlhzWOniY9aqpLO9DzZXG90OVH2trbcbNzeKVJou/57YhRPl+NgOiBl
/eGcrvRO5B/tP2o7xANKgMiF6dU53jIMm0vqMVASwwUL7Dh+ZcL1SFHySyOPN4Hl
2xWlKR3On0yhP/P3+hLllhDd1Bb7gzOnKq+dXjD084lFVLOTQSHhyBskyk2xd/oE
1xSg3/4xAgMBAAECggEAbykB5ejL0oyggPK2xKa9d0rf16xurpSKI4DaB1Wx6r3k
M4vwM/fNwdkM2Pc8stloSuu4EmplGSnE3rIov7mnxDS/fEmifjKV9UJf4OG5uEO1
4czGrYBh19Sqio2pL4UqN5bEq/spnav/a0VageBtOO+riyz3Dh1JpEsakfPWXpkk
gZ7Vl/jZ4zU27/LMfIqngOPeAGiUkLGikM6fPvm/4PbvgnSCZ4mhOSyzgCLmAWKi
Kr8zCD7BJk62/BUogk3qim+uW4Sf3RvZACTBWq6ZhWNeU2Z3CHI4G8p8sl7jtmPR
a1BWSV8Lf+83VFCfk/O+oSdb0f2z/RBAZ6uV9ZtHoQKBgQDikFsRxgXPXllSlytI
QU//19Z4S7dqWqFOX6+ap1aSyj01IsN1kvZzyGZ6ZyyAPUrNheokccijkXgooBHL
aLMxa4v0i/pHGcXAFbzIlzKwkmi0zIy7nX6cSIg2cg0sKWDGVxxJ4ODxFJRyd6Vq
Pao4/L+nUPVMRi2ME2iYe/qp/QKBgQD948teuZ4lEGTZx5IhmBpNuj45C8y5sd4W
vy+oFK8aOoTl4nCscYAAVXnS+CxInpQHI35GYRIDdjk2IL8eFThtsB+wS//Cd7h8
yY0JZC+XWhWPG5U+dSkSyzVsaK9jDJFRcnfnvHqO2+masyeq9FFTo8gX6KpF8wDL
97+UFz3xRQKBgQDa7ygx2quOodurBc2bexG1Z3smr/RD3+R0ed6VkhMEsk3HZRqA
KU3iwMrWiZDlM1VvmXKTWSjLdy0oBNZtO3W90fFilUl7H5qKbfcJ16HyIujvnaJ5
Qk4w8549DqVQAYQ05cS+V4LHNF3m51t/eKtfek4xfvgrhr1I2RCAGX42eQKBgFOw
miIgZ4vqKoRLL9VZERqcENS3GgYAJqgy31+1ab7omVQ531BInZv+kQjE+7v4Ye00
evRyHQD9IIDCLJ2a+x3VF60CcE1HL44a1h3JY5KthDvHKNwMvLxQNc0FeQLaarCB
XhsKWw/qV8fB1IqavJAohdWzwSULpDCX+xOy0Z1NAoGAPXGRPSw0p0b8zHuJ6SmM
blkpX9rdFMN08MJYIBG+ZiRobU+OOvClBZiDpYHpBnFCFpsXiStSYKOBrAAypC01
UFJJZe7Tfz1R4VcexsS3yfXOZV/+9t/PnyFofSBB8wf/dokhgfEOYq8rbiunHFVT
20/b/zX8pbSiK6Kgy9vIm7w=
-----END RSA PRIVATE KEY-----`)
