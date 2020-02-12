package main

import (
	"fmt"
	"io"
	//	"log"
	"math/rand"
	"net"
	//	"os"
	//	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Port int

type Probe []byte

type SynProber struct {
	router Router
	ip *layers.IPv4
	tcp *layers.TCP
	conn net.PacketConn

	done chan struct{}
	errs chan error
}

func NewSynProber(host string) (*SynProber, error) {
	r, err := NewRouter(host)
	if err != nil {
		return nil, err
	}
	ip := &layers.IPv4{
		SrcIP:    r.localIP,
		DstIP:    net.ParseIP(r.dstIP.String()),
		Protocol: layers.IPProtocolTCP,
	}
	fmt.Println("Setting port: ", r.localPort)
	p := layers.TCPPort(r.localPort) // typecast
	tcp := &layers.TCP{
		SrcPort: p,
		DstPort: 0000,
		Seq:     0000,
		SYN:     true,
		Window:  14600,
	}
	sp := &SynProber{router: *r, ip: ip, tcp: tcp}
	sp.done = make(chan struct{})
	sp.errs = make(chan error)

	return sp, nil
}

type Prober interface {
	Connect() error
	Send(p Probe) (int, error)
	Listen() error
}

// ProbeMaker is going to take the place of MakeProbe
type ProbeMaker interface {
	Make(dst Port) ([]byte, error)
}

// ProbeWorker is a decorator for a Prober
type ProbeSendWorker interface {
	Prober
	Work(chan Port) (chan error)
}

type ProbeListenWorker interface {
	Prober
	Work() (chan error)
}

// Connect returns a PacketConn for reading and writing bytes to the network.
// It is the caller's responsibility to close the connection.
func (sp *SynProber) Connect() error {
	var err error
	// sp.conn, err = net.ListenPacket("ip4:tcp", fmt.Sprintf("%s", sp.router.localIP))
	sp.conn, err = net.ListenPacket("ip4:tcp", fmt.Sprintf("%s", sp.router.localIP))
	if err != nil {
		return err
	}
	if addr, ok := sp.conn.LocalAddr().(*net.UDPAddr); ok {
		fmt.Println("Port is: ", addr.Port)
		sp.router.localPort = Port(addr.Port)
	} else {
		fmt.Println("Address is: ", addr)
		fmt.Println(sp.conn.LocalAddr())
	}
	return nil
}

// getFirstNetworkInterface gets the first network interface that is up
// and is not a loopback interface. It simply gets the interfaces and ranges
// over the list until the first one that satisfies criteria.
func getFirstNetworkInterface() (net.Interface, error) {
	ifis, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
	}
	for _, ifi := range ifis {
		// FlagUp is True
		if (net.FlagUp & ifi.Flags) != 0 {
			// FlabLoopback is False
			if (net.FlagLoopback & ifi.Flags) == 0 {
				return ifi, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("ERROR: Couldn't find a network interface.")
}


func (sp *SynProber) StartListening(to time.Duration) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP

	ifi, err := getFirstNetworkInterface()
	if err != nil {
		fmt.Println(err)
	}
	// get a handle to pcap livestream on the port we're sending from
	handle, err := pcap.OpenLive(ifi.Name, int32(sp.router.localPort), true, time.Microsecond * 20)
	if err != nil {
		fmt.Println("No handle! Try harder.")
	}
	defer handle.Close()
	handle.SetDirection(pcap.DirectionIn) // Does this get overwritten by BPFFilter expr?
	handle.SetBPFFilter(fmt.Sprintf("dst port %d && src host %s", int(sp.router.localPort), sp.router.dstIP.IP))

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded := []gopacket.LayerType{}

	go func() {
		sleep := 10 * time.Microsecond
		for {
			pd, ci, err := handle.ReadPacketData()
			if err == io.EOF {
				time.Sleep(sleep)
				sleep *= 2
				continue
			} else if err != nil {
				if err == pcap.NextErrorTimeoutExpired {
					// log
				} else {
					fmt.Println("ERROR: ", err)
				}
			}
			if pd != nil {
				sleep = 10 * time.Microsecond
				if err := parser.DecodeLayers(pd, &decoded); err != nil {
					fmt.Println(ci)
					continue
				}
			}
			select {
			case <- sp.done:
				return
			default:
				continue
			}
		}
	}()
}

/*
func (sp *SynProber) StartListening(to time.Duration) {
	// set a timeout
	for {
		var p []byte
		select {

		case <- sp.done:

		default:
			if err := sp.conn.SetReadDeadline(time.Now().Add(to)); err != nil {
				sp.errs <- err
			}
			n, addr, err := sp.conn.ReadFrom(p)
			if err != nil {
				sp.errs <- err
			}
			fmt.Println("Bytes: ", n, " Address: ", addr)
			fmt.Println(p)
		}
	}
}
*/
// Close wraps the connection's Close method
func (sp *SynProber) Close() error {
	return sp.conn.Close()
}

func (sp *SynProber) Send(dst Port) (int, error) {
	probe, err := sp.MakeProbe(dst)
	if err != nil {
		return 0, err
	}
	fmt.Println(probe)
	return sp.conn.WriteTo(probe, &net.IPAddr{IP: sp.router.dstIP.IP})
}

// MakeProbe calculates new TCP header values
func (sp *SynProber) MakeProbe(dst Port) ([]byte, error) {
	sp.tcp.SetNetworkLayerForChecksum(sp.ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths: true,
	}
	sp.tcp.DstPort = layers.TCPPort(dst)
	sp.tcp.Seq = rand.Uint32() / 2

	if err := gopacket.SerializeLayers(buf, opts, sp.tcp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type Router struct {
	localIP net.IP
	localPort Port
	dstIP net.IPAddr
}

func (r *Router) setHostAddress(host string) error {
	dstaddrs, err := net.LookupIP(host)
	if err != nil {
		return err
	}
	r.dstIP = net.IPAddr{IP: dstaddrs[0]}

	return nil
}


func (r *Router) setLocalAddress(host string) error {
	conn, err := net.Dial("udp", r.dstIP.String()+":8888")
	if err != nil {
		return err
	}
	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		r.localIP = addr.IP
		r.localPort = Port(addr.Port)
		fmt.Println("Set localPort = ", r.localPort)
	}
	defer conn.Close()
	return nil
}

// setAddresses just returns error condition for side effects setting the Router
// fields with data from the net library
func (r *Router) setAddresses(host string) error {
	if err := r.setHostAddress(host); err != nil {
		return err
	}
	return r.setLocalAddress(host)
}

// NewRouter configures the route
func NewRouter(host string) (*Router, error) {
	r := &Router{}
	if err := r.setAddresses(host); err != nil {
		return nil, err
	}
	return r, nil
}
