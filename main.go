package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"
	"math/rand"

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


// Probe sends a SYN packet to the port given as argument
func (s *Scanner) Probe(dstport layers.TCPPort) {
	// Our IP header... only necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    s.srcIP,
		DstIP:    s.dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: s.srcPort,
		DstPort: dstport,
		Seq:     rand.Uint32() / 2,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	// serialize for the wire
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
	}
	// write the SYN to the wire
	if _, err := s.conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: s.dstIP}); err != nil {
		log.Fatal(err)
	}

	// Set deadline so we don't wait forever.
	if err := s.conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}
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

	var dstport layers.TCPPort
	if d, err := strconv.ParseUint(os.Args[2], 10, 16); err != nil {
		log.Fatal(err)
	} else {
		dstport = layers.TCPPort(d)
	}

	handle, err := pcap.OpenLive("en0", int32(s.srcPort), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// create packetlistener
	if err := s.Connect(); err != nil {
		log.Fatal(err)
	}

	s.Probe(dstport)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.dstIP, s.srcIP)

	for {
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			log.Printf("timeout")
		} else if err != nil {
			log.Printf("err reading packet: %v, err")
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		if net := packet.NetworkLayer(); net == nil {
			//log.Printf("packet has no network layer")
		} else if net.NetworkFlow() != ipFlow {
			// ignore packets that don't match our connection
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
			// log.Printf("ipLayer is nil")
		} else if ip, ok := ipLayer.(*layers.IPv4); !ok {
			panic("ip layer is not ip layer :-/")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			// log.Printf("packet has no tcp layer")
		} else if tcp, ok := tcpLayer.(*layers.TCP); !ok {
			// We panic here because this is guaranteed to never happen.
			panic("tcp layer is not tcp layer :-/")
		} else if tcp.DstPort != layers.TCPPort(tcp.DstPort) {
			log.Printf("dst port %v does not match", tcp.DstPort)
		} else if tcp.RST {
			log.Printf("RST: src %v, dst %v, IP %v", tcp.SrcPort, tcp.DstPort, ip.SrcIP)
		} else if tcp.SYN && tcp.ACK {
			log.Printf("SYN-ACK: src %v, dst %v, IP %v", tcp.SrcPort, tcp.DstPort, ip.SrcIP)
		} else {
		}
	}
}
