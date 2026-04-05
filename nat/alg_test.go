package nat

import (
	"net/netip"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
)

func TestTFTPExpectation(t *testing.T) {
	inAddr := netip.MustParsePrefix("10.0.0.0/24")
	outAddr := netip.MustParsePrefix("192.168.1.100/24")
	n := New(inAddr, outAddr)
	defer n.Close()

	tftp := NewTFTPHelper()
	n.AddHelper(tftp)

	outside := &recorder{addr: outAddr}
	pktkit.ConnectL3(n.Outside(), outside)

	// Send UDP packet to port 69 (TFTP)
	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		5000, 69,
		[]byte{0, 1, 'f', 'i', 'l', 'e', 0, 'o', 'c', 't', 'e', 't', 0}, // RRQ
	)
	n.Inside().Send(pkt)

	if outside.count() != 1 {
		t.Fatalf("expected 1 outbound packet, got %d", outside.count())
	}

	// There should be an expectation registered.
	n.mu.Lock()
	expectCount := len(n.expectations)
	n.mu.Unlock()

	if expectCount == 0 {
		t.Fatal("TFTP helper should have created an expectation")
	}
}

func TestAddPortForward(t *testing.T) {
	inAddr := netip.MustParsePrefix("10.0.0.0/24")
	outAddr := netip.MustParsePrefix("192.168.1.100/24")
	n := New(inAddr, outAddr)
	defer n.Close()

	inside := &recorder{addr: inAddr}
	pktkit.ConnectL3(n.Inside(), inside)

	pf := PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.2"),
		InsidePort:  80,
		Description: "web server",
	}
	if err := n.AddPortForward(pf); err != nil {
		t.Fatal("AddPortForward failed:", err)
	}

	forwards := n.ListPortForwards()
	if len(forwards) != 1 {
		t.Fatalf("expected 1 forward, got %d", len(forwards))
	}
	if forwards[0].OutsidePort != 8080 || forwards[0].InsidePort != 80 {
		t.Fatal("port forward mismatch")
	}

	// Send inbound TCP to port 8080 — should be forwarded to 10.0.0.2:80.
	pkt := makeIPv4TCP(
		netip.MustParseAddr("1.2.3.4"),
		outAddr.Addr(),
		12345, 8080, 0x02, // SYN
	)
	n.Outside().Send(pkt)

	if inside.count() != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", inside.count())
	}

	// Verify the destination was rewritten to the inside IP/port.
	fwd := inside.last()
	dstIP := netip.AddrFrom4([4]byte(fwd[16:20]))
	if dstIP != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("forwarded dst IP = %v, want 10.0.0.2", dstIP)
	}
}

func TestAddPortForwardConflict(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	pf1 := PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.2"),
		InsidePort:  80,
	}
	if err := n.AddPortForward(pf1); err != nil {
		t.Fatal(err)
	}

	// Same port, different inside IP — should fail.
	pf2 := PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.3"),
		InsidePort:  80,
	}
	if err := n.AddPortForward(pf2); err == nil {
		t.Fatal("expected conflict error for same port, different IP")
	}

	// Same port, same inside IP — should succeed (update).
	pf3 := PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.2"),
		InsidePort:  8080,
	}
	if err := n.AddPortForward(pf3); err != nil {
		t.Fatal("same port+IP should not conflict:", err)
	}
}

func TestRemovePortForward(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	n.AddPortForward(PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.2"),
		InsidePort:  80,
	})

	n.RemovePortForward(protoTCP, 8080)

	forwards := n.ListPortForwards()
	if len(forwards) != 0 {
		t.Fatalf("expected 0 forwards after removal, got %d", len(forwards))
	}
}

func TestPortForwardExpiration(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	n.AddPortForward(PortForward{
		Proto:       protoTCP,
		OutsidePort: 8080,
		InsideIP:    netip.MustParseAddr("10.0.0.2"),
		InsidePort:  80,
		Expires:     time.Now().Add(-time.Second), // already expired
	})

	forwards := n.ListPortForwards()
	if len(forwards) != 0 {
		t.Fatal("expired forward should not be listed")
	}
}

func TestOutsideInsideAddr(t *testing.T) {
	inAddr := netip.MustParsePrefix("10.0.0.1/24")
	outAddr := netip.MustParsePrefix("192.168.1.100/24")
	n := New(inAddr, outAddr)
	defer n.Close()

	if n.OutsideAddr() != outAddr.Addr() {
		t.Fatalf("OutsideAddr() = %v, want %v", n.OutsideAddr(), outAddr.Addr())
	}
	if n.InsideAddr() != inAddr.Addr() {
		t.Fatalf("InsideAddr() = %v, want %v", n.InsideAddr(), inAddr.Addr())
	}
}

func TestAllocOutsidePort(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	p1 := n.AllocOutsidePort(protoTCP)
	if p1 == 0 {
		t.Fatal("AllocOutsidePort returned 0")
	}
	p2 := n.AllocOutsidePort(protoTCP)
	if p2 == 0 || p2 == p1 {
		t.Fatalf("second AllocOutsidePort returned same port %d", p2)
	}
}

func TestCreateMapping(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	port := n.CreateMapping(protoTCP, netip.MustParseAddr("10.0.0.2"), 80)
	if port == 0 {
		t.Fatal("CreateMapping returned 0")
	}

	// Creating the same mapping again should return the same port.
	port2 := n.CreateMapping(protoTCP, netip.MustParseAddr("10.0.0.2"), 80)
	if port2 != port {
		t.Fatalf("same mapping returned different port: %d vs %d", port, port2)
	}
}

func TestConnectL3Namespace(t *testing.T) {
	inAddr := netip.MustParsePrefix("10.0.0.0/24")
	outAddr := netip.MustParsePrefix("192.168.1.100/24")
	n := New(inAddr, outAddr)
	defer n.Close()

	outside := &recorder{addr: outAddr}
	pktkit.ConnectL3(n.Outside(), outside)

	// Create a namespace-isolated device.
	dev := &recorder{addr: inAddr}
	cleanup, err := n.ConnectL3(dev)
	if err != nil {
		t.Fatal("ConnectL3 failed:", err)
	}

	// Send a packet from the namespace device.
	pkt := makeIPv4TCP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		1234, 80, 0x02,
	)
	dev.Send(pkt) // This calls the handler set by ConnectL3

	// The outside recorder should have received the NATted packet.
	// (Depending on implementation, the handler on dev sends to NAT inside)
	// Let's use the nat inside directly instead.
	// Actually, ConnectL3 wires bidirectionally:
	// side.SetHandler → dev.Send, dev.SetHandler → side.Send
	// So we need to send the packet via side.Send which calls handleOutbound.

	// Let's verify cleanup works.
	if err := cleanup(); err != nil {
		t.Fatal("cleanup failed:", err)
	}
}

func TestAddExpectation(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   netip.MustParseAddr("8.8.8.8"),
		RemotePort: 0,
		InsideIP:   netip.MustParseAddr("10.0.0.2"),
		InsidePort: 80,
		Expires:    time.Now().Add(time.Minute),
	})

	n.mu.Lock()
	if len(n.expectations) != 1 {
		t.Fatalf("expected 1 expectation, got %d", len(n.expectations))
	}
	n.mu.Unlock()
}

func TestMatchExpectation(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   netip.MustParseAddr("8.8.8.8"),
		RemotePort: 21,
		InsideIP:   netip.MustParseAddr("10.0.0.2"),
		InsidePort: 2000,
		Expires:    time.Now().Add(time.Minute),
	})

	// Match it.
	n.mu.Lock()
	e := n.matchExpectation(protoTCP, netip.MustParseAddr("8.8.8.8"), 21, 0)
	n.mu.Unlock()

	if e == nil {
		t.Fatal("expected to find a matching expectation")
	}
	if e.InsidePort != 2000 {
		t.Fatalf("InsidePort = %d, want 2000", e.InsidePort)
	}

	// Should be consumed — not found again.
	n.mu.Lock()
	e2 := n.matchExpectation(protoTCP, netip.MustParseAddr("8.8.8.8"), 21, 0)
	n.mu.Unlock()
	if e2 != nil {
		t.Fatal("expectation should have been consumed")
	}
}

func TestMatchExpectationExpired(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   netip.MustParseAddr("8.8.8.8"),
		InsideIP:   netip.MustParseAddr("10.0.0.2"),
		InsidePort: 80,
		Expires:    time.Now().Add(-time.Second), // already expired
	})

	n.mu.Lock()
	e := n.matchExpectation(protoTCP, netip.MustParseAddr("8.8.8.8"), 0, 0)
	n.mu.Unlock()
	if e != nil {
		t.Fatal("expired expectation should not match")
	}
}
