package main

import (
	"fmt"

	"net"

	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestNewRoute validates that the NewRoute function succeeds when given a valid address.
func TestNewRoute(t *testing.T) {
	tcases := []struct {
		num int
		host string
		isNil bool     // specify if host should err, which should return nil
	}{
		{1, "scanme.nmap.org", false},
		{2, "127.0.0.1", false},
		{3, "htptr://blahblah.nit", true},
		{4, "257257257257", true},
	}

	for _, c := range tcases {
		r, err := NewRouter(c.host)
		if (err != nil) != c.isNil {
			t.Fatalf("Case %d failed: Expected NewRoute error to be %v for %s. Got %v.", c.num, c.isNil, c.host, r)
		}
	}
}

// TestNewSynProbeBuilder tests that we get a SynProbeBuilder as we specify
func TestNewSynProbeBuilder(t *testing.T) {
	tcases := []struct {
		num int
		host string
	}{
		{1, "www.google.com"},
		{2, "127.0.0.1"},
		{3, "scanme.nmap.org"},
	}

	for _, c := range tcases {
		//r := NewRouter(c.host)
		nspb, err := NewSynProber(c.host)
		if err != nil {
			t.Fatalf("Call to NewSynProber error: %v", err)
		}
		r := nspb.router // just extract field to inspect by shorthand for test
		if !(reflect.DeepEqual(nspb.ip.SrcIP, r.localIP)) {
			t.Fatalf("Case %d failed: Expected SynProbeBuilder LocalIP %v. Got: %v.", c.num, r.localIP, nspb.ip.SrcIP)
		}
		if !(reflect.DeepEqual(nspb.tcp.SrcPort, layers.TCPPort(int(nspb.router.localPort)))) {
			t.Fatalf("Case %d failed: Expected SynProbeBuilder LocalPort %v. Got: %v.", c.num, layers.TCPPort(int(r.localPort)), nspb.tcp.SrcPort)
		}
		if !(reflect.DeepEqual(nspb.ip.DstIP, net.ParseIP(nspb.router.dstIP.String()))) {
			t.Fatalf("Case %d failed: Expected SynProbeBuilder IP %v. Got: %v.", c.num, r.dstIP, nspb.ip.DstIP)
		}
	}
}

// TestMakeProbe
// We're going to test that TCP layer values are set appropriately
func TestMakeProbe(t *testing.T) {
	tcases := []struct {
		num int
		hostIP string
		localIP net.IP
		port Port
	}{
		{1, "123.132.123.231", net.IPv4(222, 222, 222, 222), 255},
	}

	for _, c := range tcases {
		//r := Router{c.hostIP, c.port, net.IPAddr{IP: c.localIP}}
		sp, err := NewSynProber(c.hostIP)
		if err != nil {
			t.Fatalf("Call to NewSynProber error: %v", err)
		}
		packetData, err := sp.MakeProbe(Port(c.port))
		if err != nil {
			t.Fatalf("Expected to MakeProbe without err: Case %d.", c.num)
		}

		packet := gopacket.NewPacket(packetData, layers.LayerTypeTCP, gopacket.Default)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := tcpLayer.(*layers.TCP)

		// SrcPort is set according to route calculation for local side
		if tcp.SrcPort != layers.TCPPort(sp.router.localPort) {
			t.Fatalf("Expected packet SrcPort to match route port: %d, got %d.", sp.router.localPort, tcp.DstPort)
		}

		// DstPort is specified in our test case
		if tcp.DstPort != layers.TCPPort(c.port) {
			t.Fatalf("Expected packet SrcPort to match route port: %d, got %d.", sp.router.localPort, tcp.DstPort)
		}

		// Make sure this is a SYN
		if !tcp.SYN {
			t.Fatalf("SYN flag should bet set.")
		}

		// Confirm non-SYN flags are NOT set.
		if tcp.RST || tcp.ACK {
			t.Fatalf("Only SYN flag should be set.")
		}
	}
}


func testClose(c net.PacketConn, t *testing.T) {
	if err := c.Close(); err != nil {
		t.Fatalf("Err closing: %v", err)
	}
}

// Just make sure that we get an address and a port
func TestConnect(t *testing.T) {
	testcases := []struct {
		num int
		host string
	}{
		{1, "www.google.com"},
		{2, "scanme.nmap.org"},
	}

	for _, c := range testcases {
		s, err := NewSynProber(c.host)
		if err != nil {
			t.Fatalf("Error on NewSynProber %v", err)
		}
		if err := s.Connect(); err != nil {
			t.Fatalf("Connection err: %v", err)
		}
		defer testClose(s.conn, t)

		addr := s.conn.LocalAddr()
		fmt.Println(addr.String())
		if addr.Network() != "ip" {
			t.Fatalf("Expected network to be %s: Got %s.", "ip", addr.Network())
		}
		sl := strings.Split(addr.String(), ":")
		//tcpPortStr := sl[1]
		ip := net.ParseIP(sl[0])
		if ip.IsLoopback() {
			fmt.Println(ip)
			t.Fatalf("Wanted foreign useable local address, not loopback.")
		}
	}
}


func TestProbeSelfSendLoopback(t *testing.T) {
	// TODO:(@nslaughter) replace hardcoded loopbackIP with a loop through
	// network interfaces to get address of device with loopback flag up
	lbhost := "127.0.0.1"
	sp, err := NewSynProber(lbhost)
	if err != nil {
		t.Fatalf("NewSynProber error: %v", err)
	}

	if err := sp.Connect(); err != nil {
		t.Fatalf("conection err: %v", err)
	}
	defer testClose(sp.conn, t)
	fmt.Println(sp.router.localIP)
	if _, err := sp.Send(Port(8080)); err != nil {
		t.Fatalf("Probe send error: %v", err)
	}
}

// ****************************************************************************
// ************************ IMPORTANT NOTE ************************
// Make sure probe sending tests only points to servers owned by people who
// grant explicit permission. All network tests that contact the property of
// others should be undertaken with consideration for your responsibilities.
// ****************************************************************************

func TestProbeSelfSendRemoteSpoof(t *testing.T) {
	host := "scanme.nmap.org"
	// NOTE: we swap IP here and thus will not send to any remote
	sp, err := NewSynProber(host)
	if err != nil {
		t.Fatalf("NewSynProber error: %v", err)
	}

	if err := sp.Connect(); err != nil {
		t.Fatalf("conection err: %v", err)
	}
	defer testClose(sp.conn, t)

	sp.router.dstIP = net.IPAddr{IP: sp.router.localIP}

	if _, err := sp.Send(Port(12345)); err != nil {
		t.Fatalf("Probe send error: %v", err)
	}
}


func TestSelfSendProbeListener(t *testing.T) {
		host := "scanme.nmap.org"
	// NOTE: we swap IP here and thus will not send to any remote
	sp, err := NewSynProber(host)
	if err != nil {
		t.Fatalf("NewSynProber error: %v", err)
	}

	if err := sp.Connect(); err != nil {
		t.Fatalf("conection err: %v", err)
	}
	defer testClose(sp.conn, t)

	sp.router.dstIP = net.IPAddr{IP: sp.router.localIP}
	go sp.StartListening(time.Second * 1)

	runtime.Gosched()

	fmt.Println("Sending on: ", sp.router.localPort)
	if _, err := sp.Send(sp.router.localPort); err != nil {
		t.Fatalf("Probe send error: %v", err)
	}

	runtime.Gosched()
	time.Sleep(1 * time.Second)
	runtime.Gosched()
	time.Sleep(1 * time.Second)
}
