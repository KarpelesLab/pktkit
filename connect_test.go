package pktkit

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
)

// --- L2 recorder: a minimal L2Device that records frames sent to it ---

type l2Recorder struct {
	received []Frame
	mac      net.HardwareAddr
}

func (r *l2Recorder) SetHandler(func(Frame) error) {
	// no-op: a recorder does not produce frames on its own
}

func (r *l2Recorder) Send(f Frame) error {
	// Copy the frame so we own the bytes (the contract says the buffer
	// is only valid during the callback).
	cp := make(Frame, len(f))
	copy(cp, f)
	r.received = append(r.received, cp)
	return nil
}

func (r *l2Recorder) HWAddr() net.HardwareAddr { return r.mac }
func (r *l2Recorder) Close() error             { return nil }

// --- L3 recorder: a minimal L3Device that records packets sent to it ---

type l3Recorder struct {
	received []Packet
	prefix   netip.Prefix
}

func (r *l3Recorder) SetHandler(func(Packet) error) {
	// no-op: a recorder does not produce packets on its own
}

func (r *l3Recorder) Send(pkt Packet) error {
	cp := make(Packet, len(pkt))
	copy(cp, pkt)
	r.received = append(r.received, cp)
	return nil
}

func (r *l3Recorder) Addr() netip.Prefix           { return r.prefix }
func (r *l3Recorder) SetAddr(p netip.Prefix) error { r.prefix = p; return nil }
func (r *l3Recorder) Close() error                 { return nil }

// ---------- ConnectL2 tests ----------

func TestConnectL2_PipeToRecorder(t *testing.T) {
	mac1, _ := net.ParseMAC("02:00:00:00:00:01")
	mac2, _ := net.ParseMAC("02:00:00:00:00:02")

	pipe := NewPipeL2(mac1)
	rec := &l2Recorder{mac: mac2}

	ConnectL2(pipe, rec)

	// Inject a frame into the pipe. Inject calls pipe's handler, which
	// ConnectL2 set to rec.Send, so the frame should land in rec.received.
	frame := NewFrame(mac2, mac1, EtherTypeIPv4, []byte("hello"))
	if err := pipe.Inject(frame); err != nil {
		t.Fatalf("Inject failed: %v", err)
	}

	if len(rec.received) != 1 {
		t.Fatalf("recorder got %d frames; want 1", len(rec.received))
	}
	if !bytes.Equal(rec.received[0], frame) {
		t.Fatalf("received frame differs from injected frame")
	}
}

func TestConnectL2_MultipleFrames(t *testing.T) {
	mac1, _ := net.ParseMAC("02:00:00:00:00:01")
	mac2, _ := net.ParseMAC("02:00:00:00:00:02")

	pipe := NewPipeL2(mac1)
	rec := &l2Recorder{mac: mac2}

	ConnectL2(pipe, rec)

	for i := 0; i < 5; i++ {
		frame := NewFrame(mac2, mac1, EtherTypeIPv4, []byte{byte(i)})
		if err := pipe.Inject(frame); err != nil {
			t.Fatalf("Inject %d failed: %v", i, err)
		}
	}

	if len(rec.received) != 5 {
		t.Fatalf("recorder got %d frames; want 5", len(rec.received))
	}

	// Verify each payload is distinct and correct.
	for i, f := range rec.received {
		payload := f.Payload()
		if len(payload) != 1 || payload[0] != byte(i) {
			t.Errorf("frame %d payload = %v; want [%d]", i, payload, i)
		}
	}
}

func TestConnectL2_BidirectionalWithTwoRecorders(t *testing.T) {
	// Use two recorders connected together. Since recorders have a no-op
	// SetHandler, calling Send on one won't bounce back. But we can verify
	// that the wiring is set up correctly by checking which recorder
	// receives from which pipe.

	mac1, _ := net.ParseMAC("02:00:00:00:00:01")
	mac2, _ := net.ParseMAC("02:00:00:00:00:02")

	pipeA := NewPipeL2(mac1)
	pipeB := NewPipeL2(mac2)
	recA := &l2Recorder{mac: mac1}
	recB := &l2Recorder{mac: mac2}

	// Wire: pipeA → recB and pipeB → recA
	ConnectL2(pipeA, recB)
	ConnectL2(pipeB, recA)

	frameAB := NewFrame(mac2, mac1, EtherTypeIPv4, []byte("A->B"))
	frameBA := NewFrame(mac1, mac2, EtherTypeIPv4, []byte("B->A"))

	if err := pipeA.Inject(frameAB); err != nil {
		t.Fatal(err)
	}
	if err := pipeB.Inject(frameBA); err != nil {
		t.Fatal(err)
	}

	if len(recB.received) != 1 {
		t.Fatalf("recB got %d frames; want 1", len(recB.received))
	}
	if !bytes.Equal(recB.received[0].Payload(), []byte("A->B")) {
		t.Fatalf("recB payload mismatch")
	}

	if len(recA.received) != 1 {
		t.Fatalf("recA got %d frames; want 1", len(recA.received))
	}
	if !bytes.Equal(recA.received[0].Payload(), []byte("B->A")) {
		t.Fatalf("recA payload mismatch")
	}
}

func TestConnectL2_FrameIntegrity(t *testing.T) {
	mac1, _ := net.ParseMAC("02:00:00:00:00:01")
	mac2, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")

	pipe := NewPipeL2(mac1)
	rec := &l2Recorder{mac: mac2}

	ConnectL2(pipe, rec)

	// Send a broadcast frame with a known payload.
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	frame := NewFrame(mac2, mac1, EtherTypeARP, payload)
	if err := pipe.Inject(frame); err != nil {
		t.Fatal(err)
	}

	got := rec.received[0]
	if !got.IsValid() {
		t.Fatal("received frame is not valid")
	}
	if got.EtherType() != EtherTypeARP {
		t.Fatalf("EtherType = %v; want ARP", got.EtherType())
	}
	if !bytes.Equal(got.Payload(), payload) {
		t.Fatalf("payload = %x; want %x", got.Payload(), payload)
	}
}

func TestConnectL2_NoHandlerBeforeConnect(t *testing.T) {
	mac := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	pipe := NewPipeL2(mac)

	// Inject before any handler is set: should not panic, just silently
	// drop the frame.
	frame := NewFrame(mac, mac, EtherTypeIPv4, []byte("drop"))
	if err := pipe.Inject(frame); err != nil {
		t.Fatalf("Inject with no handler returned error: %v", err)
	}
}

// ---------- ConnectL3 tests ----------

func TestConnectL3_PipeToRecorder(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.1/24")
	recPrefix := netip.MustParsePrefix("10.0.0.2/24")

	pipe := NewPipeL3(prefix)
	rec := &l3Recorder{prefix: recPrefix}

	ConnectL3(pipe, rec)

	// Build a minimal valid IPv4 packet.
	pkt := makeIPv4Packet(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ProtocolUDP, []byte("test"))

	if err := pipe.Inject(pkt); err != nil {
		t.Fatalf("Inject failed: %v", err)
	}

	if len(rec.received) != 1 {
		t.Fatalf("recorder got %d packets; want 1", len(rec.received))
	}
	if !bytes.Equal(rec.received[0], pkt) {
		t.Fatalf("received packet differs from injected packet")
	}
}

func TestConnectL3_MultiplePackets(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.1/24")
	recPrefix := netip.MustParsePrefix("10.0.0.2/24")

	pipe := NewPipeL3(prefix)
	rec := &l3Recorder{prefix: recPrefix}

	ConnectL3(pipe, rec)

	for i := 0; i < 5; i++ {
		pkt := makeIPv4Packet(
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("10.0.0.2"),
			ProtocolUDP,
			[]byte{byte(i)},
		)
		if err := pipe.Inject(pkt); err != nil {
			t.Fatalf("Inject %d failed: %v", i, err)
		}
	}

	if len(rec.received) != 5 {
		t.Fatalf("recorder got %d packets; want 5", len(rec.received))
	}
}

func TestConnectL3_PacketIntegrity(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.1/24")
	recPrefix := netip.MustParsePrefix("10.0.0.2/24")

	pipe := NewPipeL3(prefix)
	rec := &l3Recorder{prefix: recPrefix}

	ConnectL3(pipe, rec)

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	payload := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	pkt := makeIPv4Packet(src, dst, ProtocolTCP, payload)

	if err := pipe.Inject(pkt); err != nil {
		t.Fatal(err)
	}

	got := Packet(rec.received[0])
	if !got.IsValid() {
		t.Fatal("received packet is not valid")
	}
	if got.Version() != 4 {
		t.Fatalf("Version = %d; want 4", got.Version())
	}
	if got.IPv4SrcAddr() != src {
		t.Fatalf("SrcAddr = %v; want %v", got.IPv4SrcAddr(), src)
	}
	if got.IPv4DstAddr() != dst {
		t.Fatalf("DstAddr = %v; want %v", got.IPv4DstAddr(), dst)
	}
	if got.IPv4Protocol() != ProtocolTCP {
		t.Fatalf("Protocol = %v; want TCP", got.IPv4Protocol())
	}
	if !bytes.Equal(got.IPv4Payload(), payload) {
		t.Fatalf("payload = %x; want %x", got.IPv4Payload(), payload)
	}
}

func TestConnectL3_NoHandlerBeforeConnect(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.1/24")
	pipe := NewPipeL3(prefix)

	pkt := makeIPv4Packet(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		ProtocolUDP,
		[]byte("drop"),
	)
	if err := pipe.Inject(pkt); err != nil {
		t.Fatalf("Inject with no handler returned error: %v", err)
	}
}

func TestConnectL3_BidirectionalWithTwoRecorders(t *testing.T) {
	prefixA := netip.MustParsePrefix("10.0.0.1/24")
	prefixB := netip.MustParsePrefix("10.0.0.2/24")

	pipeA := NewPipeL3(prefixA)
	pipeB := NewPipeL3(prefixB)
	recA := &l3Recorder{prefix: prefixA}
	recB := &l3Recorder{prefix: prefixB}

	ConnectL3(pipeA, recB)
	ConnectL3(pipeB, recA)

	pktAB := makeIPv4Packet(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		ProtocolTCP,
		[]byte("A->B"),
	)
	pktBA := makeIPv4Packet(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		ProtocolTCP,
		[]byte("B->A"),
	)

	if err := pipeA.Inject(pktAB); err != nil {
		t.Fatal(err)
	}
	if err := pipeB.Inject(pktBA); err != nil {
		t.Fatal(err)
	}

	if len(recB.received) != 1 {
		t.Fatalf("recB got %d packets; want 1", len(recB.received))
	}
	if !bytes.Equal(Packet(recB.received[0]).IPv4Payload(), []byte("A->B")) {
		t.Fatalf("recB payload mismatch")
	}

	if len(recA.received) != 1 {
		t.Fatalf("recA got %d packets; want 1", len(recA.received))
	}
	if !bytes.Equal(Packet(recA.received[0]).IPv4Payload(), []byte("B->A")) {
		t.Fatalf("recA payload mismatch")
	}
}

// ---------- helpers ----------

// makeIPv4Packet builds a minimal valid IPv4 packet with the given fields.
// It sets a correct header checksum.
func makeIPv4Packet(src, dst netip.Addr, proto Protocol, payload []byte) Packet {
	totalLen := 20 + len(payload)
	pkt := make(Packet, totalLen)
	pkt[0] = 0x45 // Version 4, IHL 5
	pkt[1] = 0    // DSCP/ECN
	pkt[2] = byte(totalLen >> 8)
	pkt[3] = byte(totalLen)
	// Identification, Flags, Fragment Offset: leave as zero
	pkt[8] = 64          // TTL
	pkt[9] = byte(proto) // Protocol
	// Checksum at [10:12] filled below
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	copy(pkt[20:], payload)

	// Compute and fill the header checksum.
	csum := Checksum(pkt[:20])
	pkt[10] = byte(csum >> 8)
	pkt[11] = byte(csum)
	return pkt
}
