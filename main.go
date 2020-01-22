package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but use the net library to
	// populate our localIP and port.
	if conn, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}


func main() {
	if len(os.Args) != 3 {
		log.Printf("Usage: %s <host/ip> <port>\n", os.Args[0])
		os.Exit(-1)
	}
	log.Println("starting")

	// resolve host address or IP to get []string of form "x.x.x.x"
	dstaddrs, err := net.LookupIP(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// parse the dst host and port from the cmd line os.Args
	dstip := dstaddrs[0].To4()
	var dstport layers.TCPPort
	if d, err := strconv.ParseUint(os.Args[2], 10, 16); err != nil {
		log.Fatal(err)
	} else {
		dstport = layers.TCPPort(d)
	}
	fmt.Printf("Sending to ip %v on port %d\n", dstip, dstport)
	srcip, sport := localIPPort(dstip)
	fmt.Printf("Sending from ip %v on port %d\n", srcip, sport)
	srcport := layers.TCPPort(sport)
	log.Printf("using srcip: %v", srcip.String())

	// Our IP header... only necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
	}

	// connect to host
	conn, err := net.ListenPacket("ip4:tcp", fmt.Sprintf("%s", "0.0.0.0"))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	handle, err := pcap.OpenLive("en0", int32(sport), true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("writing request")
	if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}

	// Set deadline so we don't wait forever.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, ip.DstIP, ip.SrcIP)

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
			// lets ignore packets that don't match our connection
		} else if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
			log.Printf("ipLayer is nil")
		} else if ip, ok := ipLayer.(*layers.IPv4); !ok {
			panic("ip layer is not ip layer :-/")
		} else if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
			// log.Printf("packet has not tcp layer")
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
