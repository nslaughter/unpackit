package main

import (
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Scanner is the basic implementation of what we need to launch
// scans.
type Scanner struct {
	srcIP   net.IP
	dstIP   net.IP
	srcPort layers.TCPPort
	conn    net.PacketConn
}

type probe struct {
	host net.IP
	port uint64
	sendTime time.Time
}


// probeWorkers send probes to ports they take from portsCh.
// They preport when they sent the request on probesCh
func probeWorker(portsCh chan uint64, localIP net.IP, localPort layers.TCPPort, hostIP net.IP) (chan probe, chan error) {
	ip := &layers.IPv4{
		SrcIP:    localIP,
		DstIP:    hostIP,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: localPort,
		DstPort: 0000,  // her for visibiltiy - has to be set per probe
		Seq:     0000,
		SYN:     true,
		Window:  14600,
	}

	probeCh := make (chan probe)
	errCh := make (chan error)

	conn, err := net.ListenPacket("ip4:tcp", fmt.Sprintf("%s", "0.0.0.0"))
	if err != nil {
		errCh <- err
		return nil, nil
	}

	go func(ip *layers.IPv4, tcp *layers.TCP) {
		for p := range portsCh {
			tcp.SetNetworkLayerForChecksum(ip)
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}
			tcp.DstPort = layers.TCPPort(p)
			tcp.Seq = rand.Uint32() / 2
			// serialize for the wire
			if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
				errCh <- err
				//log.Fatal(err)
			}
			// write the SYN to the wire
			if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: ip.DstIP}); err != nil {
				errCh <- err
				//log.Fatal(err)
			}
			// report the successful send of this probe
			probeCh <- probe{host: ip.DstIP, port: p, sendTime: time.Now()}
		}
	}(ip, tcp)
	return probeCh, errCh
}

// straightforward address resolution. Note that this is going to be
// a few microseconds if you're recently resolved thd address and quite a
// few milliseconds if the TTL of the record is expire on this machine. So
// put this in an init or warm-up section so it won't be counted in latency stats
// and incorrectly influence program behavior or reporting.
func (s *Scanner) resolveHost(arg string) error {
	// resolve host address or IP to get a []net.IP
	dstaddrs, err := net.LookupIP(arg)
	if err != nil {
		return err
	}
	// parse the dst host and port from the cmd line os.Args
	s.dstIP = dstaddrs[0].To4()
	return nil
}

func (s *Scanner) setLocalAddress() error {
	serverAddr, err := net.ResolveUDPAddr("udp", s.dstIP.String()+":12345")
	if err != nil {
		return err
	}

	// We don't actually connect to anything, but use the net library to
	if conn, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			s.srcIP = udpaddr.IP
			s.srcPort = layers.TCPPort(udpaddr.Port)
		}
	}
	return err
}

// Connect gets a connection for sending packets
func (s *Scanner) Connect() error {
	var err error
	s.conn, err = net.ListenPacket("ip4:tcp", fmt.Sprintf("%s", "0.0.0.0"))
	if err != nil {
		return err
	}
	return nil
}

// Close releases the resources of the connection in the Scanner.
func (s *Scanner) Close() {
	s.conn.Close()
}

type packetCapture struct {
	packetData  []byte
	captureInfo gopacket.CaptureInfo
}

type tcpCapture struct {
	tcp         layers.TCP
	captureInfo gopacket.CaptureInfo
}

// capturePackets reads the wire with using h - the pcap.Handle, sends the packetCapture
// on the pcapCh channel, and quits if it reads from the done channel
func capturePackets(h *pcap.Handle, pcapCh chan<- packetCapture, done <-chan bool) {
		sleep := 10 * time.Microsecond
		for {
			pd, ci, err := h.ReadPacketData()
			if err == io.EOF {
				time.Sleep(sleep)
				log.Println("Slept ", sleep)
				sleep *= 2
			}
			if err != nil && err != io.EOF {
				if err == pcap.NextErrorTimeoutExpired {
					// log.Println("TIMEOUT: ", err)
				} else {
					log.Println("ERROR: ", err)
				}
			}
			if pd != nil {
				// ???
				pcapCh <- packetCapture{packetData: pd, captureInfo: ci}
				sleep = 10 * time.Microsecond // reset backoff
			}
			select {
			case <-done:
				return
			default:
				continue
			}
		}
}


// decodeTCP decodes our packet capture into a TCP specific representation
func decodeTCP(pcapCh <-chan packetCapture, tcpcapCh chan<- tcpCapture, done <-chan bool) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	// WARNING: decoding into layer vars not goroutine safe
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp)
	decoded := []gopacket.LayerType{}

	for {
		select {
		case pcap := <-pcapCh:
			if err := parser.DecodeLayers(pcap.packetData, &decoded); err != nil {
				// TODO(@nslaughter): some error conditions will still have useful layer info.
				log.Println(err)
				continue
			} else {
				tcpcapCh <- tcpCapture{tcp, pcap.captureInfo}
			}
		case <-done:
			return
		}
	}
}


// recordResults will just put the report from parsing the captured packets
func recordResults(results map[string][]int, tcpcapCh <-chan tcpCapture, done <-chan bool) {
	if results["RST"] == nil {
		results["RST"] = make([]int, 0)
	}
	if results["ACK"] == nil {
		results["ACK"] = make([]int, 0)
	}
	for {
		select {
		case tcpcap := <-tcpcapCh:
			if tcpcap.tcp.RST {
				results["RST"] = append(results["RST"], int(tcpcap.tcp.SrcPort))
			} else if tcpcap.tcp.SYN && tcpcap.tcp.ACK {
				results["ACK"] = append(results["ACK"], int(tcpcap.tcp.SrcPort))
			}
		case <-done:
			return
		}
	}
}

// Capture listens for packets and does something with packets that match its rules.
// This implementation with pcap is a fine proof of concept.
func (s *Scanner) Capture() {
	// get a handle to pcap livestream on the port we're sending from
	handle, err := pcap.OpenLive("en0", int32(s.srcPort), true, time.Microsecond * 20)
	if err != nil {
		log.Fatal("Kaboom!")
	}
	defer handle.Close()
	handle.SetDirection(pcap.DirectionIn) // Does this get overwritten by BPFFilter expr?
	handle.SetBPFFilter(fmt.Sprintf("dst port %d && src host %s", s.srcPort, s.dstIP))

	done := make(chan bool)
	pcapCh := make(chan packetCapture)
	tcpcapCh := make(chan tcpCapture)
	results := make(map[string][]int)

	go capturePackets(handle, pcapCh, done)
	go decodeTCP(pcapCh, tcpcapCh, done)
	go recordResults(results, tcpcapCh, done)

	time.Sleep(time.Second)
	//
	fmt.Println("RST responses: ", len(results["RST"]))
	fmt.Println("RST port list: ", results["RST"])
	fmt.Println("ACK responses: ", len(results["ACK"]))
	fmt.Println("ACK port list: ", results["ACK"])

	done <- true
	done <- true
	done <- true
}

func main() {
	if len(os.Args) != 3 {
		log.Printf("Usage: %s <host/ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}
	log.Println("starting")

	// configure scanner
	s := Scanner{}
	if err := s.resolveHost(os.Args[1]); err != nil {
		log.Fatal(err)
	}
	err := s.setLocalAddress()
	if err != nil {
		log.Fatal(err)
	}

	var d uint64
	if d, err = strconv.ParseUint(os.Args[2], 10, 16); err != nil {
		log.Fatal(err)
	} //else {

	// initialize scanner
	if err := s.Connect(); err != nil {
		log.Fatal(err)
	}
	portsCh := make(chan uint64)
	probesCh, errCh := probeWorker(portsCh, s.srcIP, s.srcPort, s.dstIP)
	portsCh <- d

	select {
	case pr := <- probesCh:
		fmt.Println(pr)
	case er := <- errCh:
		fmt.Println(er)
	}

	portsCh <- 90
	select {
	case pr := <- probesCh:
		fmt.Println(pr)
	case er := <- errCh:
		fmt.Println(er)
	}
	portsCh <- 22
	select {
	case pr := <- probesCh:
		fmt.Println(pr)
	case er := <- errCh:
		fmt.Println(er)
	}

	close(portsCh) // since it's bound to range this cleans it up

	s.Capture()
}
