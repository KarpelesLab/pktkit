//go:build !windows

package pktkit_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/qemu"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
)

// TestQEMUSocketpairARP verifies that two L2Adapters connected via a qemu
// socketpair can resolve each other's MAC addresses via ARP and exchange
// IP packets.
func TestQEMUSocketpairARP(t *testing.T) {
	a, b, err := qemu.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	// Two L3 devices with static IPs on the same subnet.
	dev1 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.1/24"))
	dev2 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.2/24"))

	// Wrap them in L2Adapters and wire the adapters to the qemu Conns.
	// The adapters handle ARP and Ethernet framing.
	adapter1 := pktkit.NewL2Adapter(dev1, nil)
	adapter2 := pktkit.NewL2Adapter(dev2, nil)
	defer adapter1.Close()
	defer adapter2.Close()

	// Wire: adapter1 ↔ qemu.Conn(a) ↔ socketpair ↔ qemu.Conn(b) ↔ adapter2
	pktkit.ConnectL2(adapter1, a)
	pktkit.ConnectL2(adapter2, b)

	// Send an IP packet from dev1 → dev2. The L2Adapter on dev1's side will
	// ARP for 10.0.0.2's MAC, the ARP request traverses the socketpair,
	// adapter2 responds, and then the IP packet is delivered.
	received := make(chan []byte, 1)
	dev2.SetHandler(func(pkt pktkit.Packet) error {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		received <- cp
		return nil
	})

	// Build a minimal UDP/IPv4 packet from 10.0.0.1 → 10.0.0.2.
	pkt := makeUDPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		5000, 5001,
		[]byte("hello via qemu socketpair"),
	)
	if err := dev1.Inject(pkt); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-received:
		p := pktkit.Packet(got)
		if p.IPv4DstAddr() != netip.MustParseAddr("10.0.0.2") {
			t.Errorf("dst = %s, want 10.0.0.2", p.IPv4DstAddr())
		}
		t.Logf("received %d-byte packet via ARP + socketpair", len(got))
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet (ARP resolution may have failed)")
	}
}

// TestQEMUSocketpairDHCP verifies DHCP works over a qemu socketpair link.
func TestQEMUSocketpairDHCP(t *testing.T) {
	a, b, err := qemu.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	// Server side: L2Hub with DHCP server.
	hub := pktkit.NewL2Hub()
	dhcp := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("192.168.50.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("192.168.50.10"),
		RangeEnd:   netip.MustParseAddr("192.168.50.50"),
		Router:     netip.MustParseAddr("192.168.50.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	})
	hub.Connect(dhcp)
	hub.Connect(a) // server side of the socketpair

	// Client side: vclient with L2Adapter doing DHCP.
	client := vclient.New()
	defer client.Close()
	adapter := pktkit.NewL2Adapter(client, nil)
	defer adapter.Close()
	pktkit.ConnectL2(adapter, b)
	adapter.StartDHCP()

	// Wait for DHCP to assign an address.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addr := client.Addr()
		if addr.IsValid() && addr.Addr().IsPrivate() {
			t.Logf("client got IP via DHCP over socketpair: %s", addr)
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("DHCP failed: client never got an address")
}

// TestQEMUSocketpairHTTP builds a full network topology over a socketpair:
//
//	Side A (server): L2Hub + DHCP + slirp + HTTP server
//	   ↕ qemu socketpair
//	Side B (client): vclient with DHCP
//
// The client fetches a page from the HTTP server through the socketpair link.
func TestQEMUSocketpairHTTP(t *testing.T) {
	qa, qb, err := qemu.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer qa.Close()
	defer qb.Close()

	// --- Server side ---
	hub := pktkit.NewL2Hub()

	dhcp := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("10.99.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("10.99.0.10"),
		RangeEnd:   netip.MustParseAddr("10.99.0.50"),
		Router:     netip.MustParseAddr("10.99.0.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("8.8.8.8")},
	})
	hub.Connect(dhcp)

	// Slirp for gateway/NAT (also serves as the router at .1).
	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("10.99.0.1/24"))
	hub.Connect(pktkit.NewL2Adapter(stack, nil))

	// HTTP server on a vclient at .2.
	serverClient := vclient.New()
	defer serverClient.Close()
	serverClient.SetIP(net.IPv4(10, 99, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 99, 0, 1))
	hub.Connect(pktkit.NewL2Adapter(serverClient, nil))

	ln, err := serverClient.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "pong from %s", r.RemoteAddr)
	})
	go http.Serve(ln, mux)

	// Connect the server hub to the socketpair.
	hub.Connect(qa)

	// --- Client side ---
	testClient := vclient.New()
	defer testClient.Close()
	testClient.SetDNS([]net.IP{net.IPv4(8, 8, 8, 8)})

	clientAdapter := pktkit.NewL2Adapter(testClient, nil)
	defer clientAdapter.Close()
	pktkit.ConnectL2(clientAdapter, qb)
	clientAdapter.StartDHCP()

	// Wait for DHCP.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addr := testClient.Addr()
		if addr.IsValid() && addr.Addr().IsPrivate() {
			t.Logf("client IP: %s", addr)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr := testClient.Addr(); !addr.IsValid() || !addr.Addr().IsPrivate() {
		t.Fatalf("DHCP failed: addr = %s", testClient.Addr())
	}

	// Fetch the HTTP endpoint through the socketpair.
	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: testClient.DialContext},
		Timeout:   10 * time.Second,
	}

	resp, err := httpClient.Get("http://10.99.0.2:8080/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t.Logf("response: %s", string(body))

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "pong") {
		t.Fatalf("unexpected body: %s", body)
	}
}

// TestQEMUSocketpairBidirectionalTCP sets up TCP servers on both sides of
// a socketpair and verifies bidirectional communication.
func TestQEMUSocketpairBidirectionalTCP(t *testing.T) {
	qa, qb, err := qemu.Socketpair()
	if err != nil {
		t.Fatal(err)
	}
	defer qa.Close()
	defer qb.Close()

	hub := pktkit.NewL2Hub()

	// Side A: vclient at 10.50.0.1
	clientA := vclient.New()
	defer clientA.Close()
	clientA.SetIP(net.IPv4(10, 50, 0, 1), net.CIDRMask(24, 32), net.IPv4(10, 50, 0, 1))
	adapterA := pktkit.NewL2Adapter(clientA, nil)
	defer adapterA.Close()
	hub.Connect(adapterA)

	// Side B: vclient at 10.50.0.2 (connected via socketpair)
	clientB := vclient.New()
	defer clientB.Close()
	clientB.SetIP(net.IPv4(10, 50, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 50, 0, 1))
	adapterB := pktkit.NewL2Adapter(clientB, nil)
	defer adapterB.Close()

	// Wire: hub ↔ qa ↔ socketpair ↔ qb ↔ adapterB
	hub.Connect(qa)
	pktkit.ConnectL2(adapterB, qb)

	// TCP server on A.
	lnA, err := clientA.Listen("tcp", "0.0.0.0:7001")
	if err != nil {
		t.Fatal(err)
	}
	defer lnA.Close()
	go func() {
		for {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				conn.Write([]byte("A:" + string(buf[:n])))
			}()
		}
	}()

	// TCP server on B.
	lnB, err := clientB.Listen("tcp", "0.0.0.0:7002")
	if err != nil {
		t.Fatal(err)
	}
	defer lnB.Close()
	go func() {
		for {
			conn, err := lnB.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				conn.Write([]byte("B:" + string(buf[:n])))
			}()
		}
	}()

	// B dials A.
	t.Run("B_to_A", func(t *testing.T) {
		conn, err := clientB.Dial("tcp", "10.50.0.1:7001")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("hello"))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); got != "A:hello" {
			t.Errorf("got %q, want %q", got, "A:hello")
		}
	})

	// A dials B.
	t.Run("A_to_B", func(t *testing.T) {
		conn, err := clientA.Dial("tcp", "10.50.0.2:7002")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.Write([]byte("world"))
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(buf[:n]); got != "B:world" {
			t.Errorf("got %q, want %q", got, "B:world")
		}
	})
}

// --- Benchmarks ---

// BenchmarkQEMUSocketpairL2 measures raw L2 frame throughput through a
// socketpair (no IP stack, no ARP — just the qemu framing layer).
func BenchmarkQEMUSocketpairL2(b *testing.B) {
	qa, qb, err := qemu.Socketpair()
	if err != nil {
		b.Fatal(err)
	}
	defer qa.Close()
	defer qb.Close()

	// Sink handler.
	qb.SetHandler(func(pktkit.Frame) error { return nil })

	frame := pktkit.NewFrame(
		qb.HWAddr(), qa.HWAddr(),
		pktkit.EtherTypeIPv4, make([]byte, 1500),
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		qa.Send(frame)
	}
}

// BenchmarkQEMUSocketpairL2Hub measures frame forwarding through an L2Hub
// with one port exiting via a qemu socketpair.
// Topology: pipe → L2Hub → qa → socketpair → qb (sink)
func BenchmarkQEMUSocketpairL2Hub(b *testing.B) {
	qa, qb, err := qemu.Socketpair()
	if err != nil {
		b.Fatal(err)
	}
	defer qa.Close()
	defer qb.Close()

	// qb is a standalone sink — NOT connected to the hub.
	qb.SetHandler(func(pktkit.Frame) error { return nil })

	hub := pktkit.NewL2Hub()

	// Only qa is connected to the hub as an exit port.
	ha := hub.Connect(qa)
	defer ha.Close()

	// A local pipe injects frames into the hub.
	pipe := pktkit.NewPipeL2(net.HardwareAddr{0x02, 0xBB, 0x00, 0x00, 0x00, 0x01})
	hp := hub.Connect(pipe)
	defer hp.Close()

	// Frame addressed to qa's MAC → hub routes to qa → socket → qb (sink).
	frame := pktkit.NewFrame(qa.HWAddr(), pipe.HWAddr(), pktkit.EtherTypeIPv4, make([]byte, 1500))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipe.Inject(frame)
	}
}

// BenchmarkQEMUSocketpairTCPThroughput measures TCP throughput through a
// full stack: vclient → L2Adapter → L2Hub → qemu socketpair → L2Adapter → vclient.
func BenchmarkQEMUSocketpairTCPThroughput(b *testing.B) {
	qa, qb, err := qemu.Socketpair()
	if err != nil {
		b.Fatal(err)
	}
	defer qa.Close()
	defer qb.Close()

	hub := pktkit.NewL2Hub()

	// Server at 10.77.0.1
	server := vclient.New()
	defer server.Close()
	server.SetIP(net.IPv4(10, 77, 0, 1), net.CIDRMask(24, 32), net.IPv4(10, 77, 0, 1))
	srvAdapter := pktkit.NewL2Adapter(server, nil)
	defer srvAdapter.Close()
	hub.Connect(srvAdapter)
	hub.Connect(qa)

	// Client at 10.77.0.2 via socketpair
	client := vclient.New()
	defer client.Close()
	client.SetIP(net.IPv4(10, 77, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 77, 0, 1))
	cliAdapter := pktkit.NewL2Adapter(client, nil)
	defer cliAdapter.Close()
	pktkit.ConnectL2(cliAdapter, qb)

	// TCP echo server.
	ln, err := server.Listen("tcp", "0.0.0.0:9000")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	// Dial from client → server.
	conn, err := client.Dial("tcp", "10.77.0.1:9000")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	data := make([]byte, 1400)
	readBuf := make([]byte, 1400)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(data); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, readBuf); err != nil {
			b.Fatal(err)
		}
	}
}

// --- helpers ---

func makeUDPPacket(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) pktkit.Packet {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	pkt[8] = 64
	pkt[9] = 17 // UDP
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])

	// UDP header
	pkt[ihl] = byte(srcPort >> 8)
	pkt[ihl+1] = byte(srcPort)
	pkt[ihl+2] = byte(dstPort >> 8)
	pkt[ihl+3] = byte(dstPort)
	pkt[ihl+4] = byte(udpLen >> 8)
	pkt[ihl+5] = byte(udpLen)
	copy(pkt[ihl+8:], payload)

	// Set total length and compute IP checksum.
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	csum := pktkit.Checksum(pkt[:ihl])
	pkt[10] = byte(csum >> 8)
	pkt[11] = byte(csum)

	return pkt
}
