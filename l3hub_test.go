package pktkit

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
)

// l3Spy records packets and can inject packets through its handler.
type l3Spy struct {
	mu       sync.Mutex
	received []Packet
	handler  func(Packet) error
	prefix   netip.Prefix
}

func newL3Spy(prefix netip.Prefix) *l3Spy {
	return &l3Spy{prefix: prefix}
}

func (s *l3Spy) SetHandler(h func(Packet) error) { s.handler = h }
func (s *l3Spy) Send(pkt Packet) error {
	cp := make(Packet, len(pkt))
	copy(cp, pkt)
	s.mu.Lock()
	s.received = append(s.received, cp)
	s.mu.Unlock()
	return nil
}
func (s *l3Spy) Addr() netip.Prefix           { return s.prefix }
func (s *l3Spy) SetAddr(p netip.Prefix) error { s.prefix = p; return nil }
func (s *l3Spy) Close() error                 { return nil }

func (s *l3Spy) inject(pkt Packet) {
	if s.handler != nil {
		s.handler(pkt)
	}
}

func (s *l3Spy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

// makeTestIPv4 builds a minimal valid IPv4 packet with the given src/dst.
func makeTestIPv4(src, dst netip.Addr) Packet {
	pkt := make(Packet, 24)                  // 20-byte header + 4 payload
	pkt[0] = 0x45                            // version=4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 24) // total length
	pkt[8] = 64                              // TTL
	pkt[9] = 6                               // TCP
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	// IP checksum (zero for test purposes is fine)
	return pkt
}

func TestL3Hub_UnicastRouting(t *testing.T) {
	hub := NewL3Hub()
	a := newL3Spy(netip.MustParsePrefix("10.0.0.1/24"))
	b := newL3Spy(netip.MustParsePrefix("10.0.1.1/24"))
	c := newL3Spy(netip.MustParsePrefix("10.0.2.1/24"))
	hub.Connect(a)
	hub.Connect(b)
	hub.Connect(c)

	// Send from a to 10.0.1.50 — should route to b (10.0.1.0/24 contains it).
	pkt := makeTestIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.1.50"))
	a.inject(pkt)

	if b.count() != 1 {
		t.Errorf("b should receive unicast: got %d", b.count())
	}
	if c.count() != 0 {
		t.Errorf("c should not receive unicast to b's subnet: got %d", c.count())
	}
	if a.count() != 0 {
		t.Error("source should not receive its own packet")
	}
}

func TestL3Hub_BroadcastDelivery(t *testing.T) {
	hub := NewL3Hub()
	a := newL3Spy(netip.MustParsePrefix("10.0.0.1/24"))
	b := newL3Spy(netip.MustParsePrefix("10.0.1.1/24"))
	hub.Connect(a)
	hub.Connect(b)

	// Broadcast (255.255.255.255) — should go to all except source.
	pkt := makeTestIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("255.255.255.255"))
	a.inject(pkt)

	if b.count() != 1 {
		t.Errorf("b should receive broadcast: got %d", b.count())
	}
}

func TestL3Hub_MulticastDelivery(t *testing.T) {
	hub := NewL3Hub()
	a := newL3Spy(netip.MustParsePrefix("10.0.0.1/24"))
	b := newL3Spy(netip.MustParsePrefix("10.0.1.1/24"))
	c := newL3Spy(netip.MustParsePrefix("10.0.2.1/24"))
	hub.Connect(a)
	hub.Connect(b)
	hub.Connect(c)

	pkt := makeTestIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("224.0.0.1"))
	a.inject(pkt)

	if b.count() != 1 || c.count() != 1 {
		t.Errorf("multicast should go to all: b=%d c=%d", b.count(), c.count())
	}
}

func TestL3Hub_NoMatchDrops(t *testing.T) {
	hub := NewL3Hub()
	a := newL3Spy(netip.MustParsePrefix("10.0.0.1/24"))
	b := newL3Spy(netip.MustParsePrefix("10.0.1.1/24"))
	hub.Connect(a)
	hub.Connect(b)

	// Send to an IP not in any port's prefix — should be dropped.
	pkt := makeTestIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("192.168.99.1"))
	a.inject(pkt)

	if b.count() != 0 {
		t.Errorf("unroutable unicast should be dropped: b=%d", b.count())
	}
}

func TestL3Hub_Disconnect(t *testing.T) {
	hub := NewL3Hub()
	a := newL3Spy(netip.MustParsePrefix("10.0.0.1/24"))
	b := newL3Spy(netip.MustParsePrefix("10.0.1.1/24"))
	hub.Connect(a)
	hb := hub.Connect(b)

	hb.Close()

	pkt := makeTestIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.1.50"))
	a.inject(pkt)

	if b.count() != 0 {
		t.Error("disconnected device should not receive packets")
	}
}
