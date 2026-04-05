package pktkit

import (
	"net"
	"sync"
	"testing"
)

// l2Spy records frames received and can inject frames through its handler.
type l2Spy struct {
	mu       sync.Mutex
	received []Frame
	handler  func(Frame) error
	mac      net.HardwareAddr
}

func newL2Spy(mac net.HardwareAddr) *l2Spy {
	return &l2Spy{mac: mac}
}

func (s *l2Spy) SetHandler(h func(Frame) error) { s.handler = h }
func (s *l2Spy) Send(f Frame) error {
	cp := make(Frame, len(f))
	copy(cp, f)
	s.mu.Lock()
	s.received = append(s.received, cp)
	s.mu.Unlock()
	return nil
}
func (s *l2Spy) HWAddr() net.HardwareAddr { return s.mac }
func (s *l2Spy) Close() error             { return nil }

// inject simulates the device producing a frame (calls its handler).
func (s *l2Spy) inject(f Frame) {
	if s.handler != nil {
		s.handler(f)
	}
}

func (s *l2Spy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.received)
}

func TestL2Hub_Flood_UnknownUnicast(t *testing.T) {
	hub := NewL2Hub()
	a := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	b := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	c := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 3})
	hub.Connect(a)
	hub.Connect(b)
	hub.Connect(c)

	// Unknown unicast dst — should flood to b and c (not back to a).
	frame := NewFrame(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 0xFF}, // unknown dst
		a.mac,
		EtherTypeIPv4,
		[]byte{1, 2, 3},
	)
	a.inject(frame)

	if a.count() != 0 {
		t.Error("source should not receive its own frame")
	}
	if b.count() != 1 {
		t.Errorf("b should receive 1 frame, got %d", b.count())
	}
	if c.count() != 1 {
		t.Errorf("c should receive 1 frame, got %d", c.count())
	}
}

func TestL2Hub_Broadcast_Floods(t *testing.T) {
	hub := NewL2Hub()
	a := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	b := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	c := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 3})
	hub.Connect(a)
	hub.Connect(b)
	hub.Connect(c)

	frame := NewFrame(broadcastMAC, a.mac, EtherTypeARP, []byte{0})
	a.inject(frame)

	if b.count() != 1 || c.count() != 1 {
		t.Errorf("broadcast should flood: b=%d c=%d", b.count(), c.count())
	}
	if a.count() != 0 {
		t.Error("source should not receive broadcast back")
	}
}

func TestL2Hub_Multicast_Floods(t *testing.T) {
	hub := NewL2Hub()
	a := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	b := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	hub.Connect(a)
	hub.Connect(b)

	// Multicast MAC: first byte has bit 0 set.
	mcastDst := net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01}
	frame := NewFrame(mcastDst, a.mac, EtherTypeIPv4, []byte{0})
	a.inject(frame)

	if b.count() != 1 {
		t.Errorf("multicast should flood: b=%d", b.count())
	}
}

func TestL2Hub_MACLearning_Unicast(t *testing.T) {
	hub := NewL2Hub()
	a := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	b := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	c := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 3})
	hub.Connect(a)
	hub.Connect(b)
	hub.Connect(c)

	// Step 1: b sends a frame so the switch learns b's MAC → port.
	frame1 := NewFrame(broadcastMAC, b.mac, EtherTypeARP, []byte{0})
	b.inject(frame1)
	// a and c should receive the broadcast.

	// Step 2: a sends a unicast to b's MAC. The switch should deliver only to b.
	frame2 := NewFrame(b.mac, a.mac, EtherTypeIPv4, []byte{1, 2})
	aCountBefore := a.count()
	bCountBefore := b.count()
	cCountBefore := c.count()

	a.inject(frame2)

	if a.count() != aCountBefore {
		t.Error("source should not receive its own frame")
	}
	if b.count() != bCountBefore+1 {
		t.Errorf("b should receive unicast: got %d, want %d", b.count(), bCountBefore+1)
	}
	if c.count() != cCountBefore {
		t.Errorf("c should NOT receive learned unicast: got %d, want %d", c.count(), cCountBefore)
	}
}

func TestL2Hub_Disconnect_CleansMAC(t *testing.T) {
	hub := NewL2Hub()
	a := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 1})
	b := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
	c := newL2Spy(net.HardwareAddr{0x02, 0, 0, 0, 0, 3})
	hub.Connect(a)
	hb := hub.Connect(b)
	hub.Connect(c)

	// Learn b's MAC.
	b.inject(NewFrame(broadcastMAC, b.mac, EtherTypeARP, []byte{0}))

	// Disconnect b.
	hb.Close()

	// Send unicast to b's MAC from a. Since b is disconnected and MAC cleaned,
	// it should flood to c (and b should get nothing since it's disconnected).
	bBefore := b.count()
	a.inject(NewFrame(b.mac, a.mac, EtherTypeIPv4, []byte{1}))

	if b.count() != bBefore {
		t.Error("disconnected device should not receive frames")
	}
	if c.count() < 2 { // 1 from broadcast + 1 from flood
		t.Errorf("c should receive flooded frame after b disconnected: got %d", c.count())
	}
}
