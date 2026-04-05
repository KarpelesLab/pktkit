package nat

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// makeIPv6TCP builds a minimal IPv6+TCP packet.
func makeIPv6TCP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags byte) pktkit.Packet {
	tcpHL := 20
	pktLen := ipv6HeaderLen + tcpHL
	pkt := make(pktkit.Packet, pktLen)

	// IPv6 header
	pkt[0] = 0x60 // version=6
	binary.BigEndian.PutUint16(pkt[4:6], uint16(tcpHL)) // payload length
	pkt[6] = protoTCP                                    // next header
	pkt[7] = 64                                          // hop limit
	s := srcIP.As16()
	d := dstIP.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])

	// TCP header
	tcp := pkt[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 5 << 4 // data offset
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window

	// TCP checksum with pseudo-header
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	csum := computeTransportChecksum(protoTCP, srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	return pkt
}

// makeIPv6UDP builds a minimal IPv6+UDP packet.
func makeIPv6UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) pktkit.Packet {
	udpLen := 8 + len(payload)
	pktLen := ipv6HeaderLen + udpLen
	pkt := make(pktkit.Packet, pktLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(udpLen))
	pkt[6] = protoUDP
	pkt[7] = 64
	s := srcIP.As16()
	d := dstIP.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])

	udp := pkt[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)

	// UDP checksum (mandatory for IPv6)
	binary.BigEndian.PutUint16(udp[6:8], 0)
	csum := computeTransportChecksum(protoUDP, srcIP, dstIP, udp)
	if csum == 0 {
		csum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], csum)

	return pkt
}

// makeIPv6ICMPEchoRequest builds an ICMPv6 Echo Request.
func makeIPv6ICMPEchoRequest(srcIP, dstIP netip.Addr, id, seq uint16) pktkit.Packet {
	icmpLen := 8
	pktLen := ipv6HeaderLen + icmpLen
	pkt := make(pktkit.Packet, pktLen)

	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(icmpLen))
	pkt[6] = protoICMPv6
	pkt[7] = 64
	s := srcIP.As16()
	d := dstIP.As16()
	copy(pkt[8:24], s[:])
	copy(pkt[24:40], d[:])

	icmp := pkt[ipv6HeaderLen:]
	icmp[0] = 128 // Echo Request
	icmp[1] = 0
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)

	binary.BigEndian.PutUint16(icmp[2:4], 0)
	binary.BigEndian.PutUint16(icmp[2:4], computeICMPv6Checksum(srcIP, dstIP, icmp))

	return pkt
}

// nat64Recorder captures packets sent to the inside or outside.
type nat64Recorder struct {
	mu       sync.Mutex
	received []pktkit.Packet
	addr     netip.Prefix
}

func (r *nat64Recorder) handler() func(pktkit.Packet) error {
	return func(pkt pktkit.Packet) error {
		cp := make(pktkit.Packet, len(pkt))
		copy(cp, pkt)
		r.mu.Lock()
		r.received = append(r.received, cp)
		r.mu.Unlock()
		return nil
	}
}

func (r *nat64Recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.received)
}

func (r *nat64Recorder) last() pktkit.Packet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received[len(r.received)-1]
}

func TestIPv4MappedHelpers(t *testing.T) {
	mapped := ipv4ToMapped(netip.MustParseAddr("192.168.1.1"))
	if !isIPv4Mapped(mapped) {
		t.Fatal("ipv4ToMapped result should be IPv4-mapped")
	}

	extracted := ipv4FromMapped(mapped)
	if extracted != netip.MustParseAddr("192.168.1.1") {
		t.Fatalf("ipv4FromMapped = %v, want 192.168.1.1", extracted)
	}

	// Non-mapped IPv6 address
	if isIPv4Mapped(netip.MustParseAddr("2001:db8::1")) {
		t.Fatal("2001:db8::1 should not be IPv4-mapped")
	}

	// Loopback
	mapped2 := ipv4ToMapped(netip.MustParseAddr("127.0.0.1"))
	got := ipv4FromMapped(mapped2)
	if got != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("roundtrip 127.0.0.1: got %v", got)
	}
}

func TestNAT64TCPOutbound(t *testing.T) {
	insidePrefix := netip.MustParsePrefix("fd00::1/120")
	outsidePrefix := netip.MustParsePrefix("192.168.1.100/24")

	n := NewNAT64(insidePrefix, outsidePrefix)
	defer n.Close()

	outsideRec := &nat64Recorder{}
	n.Outside().SetHandler(outsideRec.handler())

	// Send IPv6 TCP SYN from inside to an IPv4-mapped destination.
	srcIPv6 := netip.MustParseAddr("fd00::2")
	dstIPv4 := netip.MustParseAddr("10.0.0.1")
	dstIPv6Mapped := ipv4ToMapped(dstIPv4)

	pkt := makeIPv6TCP(srcIPv6, dstIPv6Mapped, 12345, 80, 0x02) // SYN
	n.Inside().Send(pkt)

	if outsideRec.count() != 1 {
		t.Fatalf("expected 1 outbound packet, got %d", outsideRec.count())
	}

	out := outsideRec.last()
	// Verify it's IPv4
	if out[0]>>4 != 4 {
		t.Fatal("expected IPv4 packet")
	}
	// Verify protocol
	if out[9] != protoTCP {
		t.Fatalf("expected TCP proto, got %d", out[9])
	}
	// Verify destination IP
	dstOut := netip.AddrFrom4([4]byte(out[16:20]))
	if dstOut != dstIPv4 {
		t.Fatalf("dst IP = %v, want %v", dstOut, dstIPv4)
	}
	// Source should be the NAT64 outside address
	srcOut := netip.AddrFrom4([4]byte(out[12:16]))
	if srcOut != outsidePrefix.Addr() {
		t.Fatalf("src IP = %v, want %v", srcOut, outsidePrefix.Addr())
	}
}

func TestNAT64UDPOutbound(t *testing.T) {
	n := NewNAT64(
		netip.MustParsePrefix("fd00::1/120"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	outsideRec := &nat64Recorder{}
	n.Outside().SetHandler(outsideRec.handler())

	srcIPv6 := netip.MustParseAddr("fd00::5")
	dstIPv4 := netip.MustParseAddr("8.8.8.8")
	dstIPv6Mapped := ipv4ToMapped(dstIPv4)

	pkt := makeIPv6UDP(srcIPv6, dstIPv6Mapped, 5000, 53, []byte("dns query"))
	n.Inside().Send(pkt)

	if outsideRec.count() != 1 {
		t.Fatalf("expected 1 outbound packet, got %d", outsideRec.count())
	}

	out := outsideRec.last()
	if out[9] != protoUDP {
		t.Fatalf("expected UDP proto, got %d", out[9])
	}
	// Verify dst port preserved
	ihl := int(out[0]&0x0F) * 4
	dstPort := binary.BigEndian.Uint16(out[ihl+2 : ihl+4])
	if dstPort != 53 {
		t.Fatalf("dst port = %d, want 53", dstPort)
	}
}

func TestNAT64TCPInbound(t *testing.T) {
	n := NewNAT64(
		netip.MustParsePrefix("fd00::1/120"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	insideRec := &nat64Recorder{}
	n.Inside().SetHandler(insideRec.handler())

	outsideRec := &nat64Recorder{}
	n.Outside().SetHandler(outsideRec.handler())

	// First, send outbound to create a mapping.
	srcIPv6 := netip.MustParseAddr("fd00::2")
	dstIPv4 := netip.MustParseAddr("10.0.0.1")
	dstIPv6Mapped := ipv4ToMapped(dstIPv4)

	outPkt := makeIPv6TCP(srcIPv6, dstIPv6Mapped, 12345, 80, 0x02)
	n.Inside().Send(outPkt)

	if outsideRec.count() != 1 {
		t.Fatal("outbound not sent")
	}

	// Read the mapped source port from the outbound packet.
	outV4 := outsideRec.last()
	ihl := int(outV4[0]&0x0F) * 4
	mappedPort := binary.BigEndian.Uint16(outV4[ihl : ihl+2])

	// Now send a reply from the IPv4 side back to the mapped port.
	replyPkt := makeIPv4TCP(dstIPv4, netip.MustParseAddr("192.168.1.100"), 80, mappedPort, 0x12) // SYN-ACK
	n.Outside().Send(replyPkt)

	if insideRec.count() != 1 {
		t.Fatalf("expected 1 inbound packet, got %d", insideRec.count())
	}

	in := insideRec.last()
	// Verify it's IPv6
	if in[0]>>4 != 6 {
		t.Fatal("expected IPv6 packet")
	}
	// Verify destination is the original IPv6 client
	dstV6 := netip.AddrFrom16([16]byte(in[24:40]))
	if dstV6 != srcIPv6 {
		t.Fatalf("dst IPv6 = %v, want %v", dstV6, srcIPv6)
	}
	// Verify destination port is the original client port
	tcp := in[ipv6HeaderLen:]
	gotDstPort := binary.BigEndian.Uint16(tcp[2:4])
	if gotDstPort != 12345 {
		t.Fatalf("dst port = %d, want 12345", gotDstPort)
	}
}

func TestNAT64ICMPv6Echo(t *testing.T) {
	n := NewNAT64(
		netip.MustParsePrefix("fd00::1/120"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	outsideRec := &nat64Recorder{}
	n.Outside().SetHandler(outsideRec.handler())

	insideRec := &nat64Recorder{}
	n.Inside().SetHandler(insideRec.handler())

	srcIPv6 := netip.MustParseAddr("fd00::3")
	dstIPv4 := netip.MustParseAddr("8.8.4.4")
	dstIPv6Mapped := ipv4ToMapped(dstIPv4)

	pkt := makeIPv6ICMPEchoRequest(srcIPv6, dstIPv6Mapped, 0x1234, 1)
	n.Inside().Send(pkt)

	if outsideRec.count() != 1 {
		t.Fatalf("expected 1 outbound ICMP, got %d", outsideRec.count())
	}

	out := outsideRec.last()
	// Should be ICMPv4 (proto 1)
	if out[9] != protoICMP {
		t.Fatalf("expected ICMP proto, got %d", out[9])
	}
	// Type should be 8 (Echo Request)
	ihl := int(out[0]&0x0F) * 4
	if out[ihl] != 8 {
		t.Fatalf("ICMP type = %d, want 8 (Echo Request)", out[ihl])
	}

	// Now send an echo reply back
	mappedID := binary.BigEndian.Uint16(out[ihl+4 : ihl+6])
	reply := makeICMPEchoReply(dstIPv4, netip.MustParseAddr("192.168.1.100"), mappedID, 1)
	n.Outside().Send(reply)

	if insideRec.count() != 1 {
		t.Fatalf("expected 1 inbound ICMPv6, got %d", insideRec.count())
	}

	in := insideRec.last()
	// Should be ICMPv6
	if in[6] != protoICMPv6 {
		t.Fatalf("expected ICMPv6 next header, got %d", in[6])
	}
	icmp := in[ipv6HeaderLen:]
	// Type 129 = Echo Reply
	if icmp[0] != 129 {
		t.Fatalf("ICMPv6 type = %d, want 129 (Echo Reply)", icmp[0])
	}
	// Identifier should be restored to original
	gotID := binary.BigEndian.Uint16(icmp[4:6])
	if gotID != 0x1234 {
		t.Fatalf("ICMPv6 id = 0x%04x, want 0x1234", gotID)
	}
}

func TestNAT64NonMappedDropped(t *testing.T) {
	n := NewNAT64(
		netip.MustParsePrefix("fd00::1/120"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	outsideRec := &nat64Recorder{}
	n.Outside().SetHandler(outsideRec.handler())

	// Send to a non IPv4-mapped destination — should be dropped.
	pkt := makeIPv6TCP(
		netip.MustParseAddr("fd00::2"),
		netip.MustParseAddr("2001:db8::1"), // not IPv4-mapped
		1234, 80, 0x02,
	)
	n.Inside().Send(pkt)

	if outsideRec.count() != 0 {
		t.Fatal("non IPv4-mapped destination should be dropped")
	}
}

func TestNAT64Close(t *testing.T) {
	n := NewNAT64(
		netip.MustParsePrefix("fd00::1/120"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	n.Close()
	// Double close should not panic.
	n.Close()
}

func TestICMPv4ToV6DestUnreach(t *testing.T) {
	tests := []struct {
		code     uint8
		wantType uint8
		wantCode uint8
	}{
		{0, 1, 0},  // Net Unreachable
		{1, 1, 0},  // Host Unreachable
		{2, 4, 1},  // Protocol Unreachable → Parameter Problem
		{3, 1, 4},  // Port Unreachable
		{4, 0, 0},  // Fragmentation Needed (not mapped here)
		{5, 1, 5},  // Source Route Failed
		{6, 1, 0},  // Dest network unknown
		{9, 1, 1},  // Admin prohibited
		{13, 1, 1}, // Communication admin prohibited
		{15, 0, 0}, // Unknown code → dropped
	}

	for _, tc := range tests {
		gotType, gotCode := icmpv4ToV6DestUnreach(tc.code)
		if gotType != tc.wantType || gotCode != tc.wantCode {
			t.Errorf("icmpv4ToV6DestUnreach(%d) = (%d,%d), want (%d,%d)",
				tc.code, gotType, gotCode, tc.wantType, tc.wantCode)
		}
	}
}

func TestNAT64Addresses(t *testing.T) {
	insidePrefix := netip.MustParsePrefix("fd00::1/120")
	outsidePrefix := netip.MustParsePrefix("192.168.1.100/24")

	n := NewNAT64(insidePrefix, outsidePrefix)
	defer n.Close()

	if n.Inside().Addr() != insidePrefix {
		t.Fatalf("Inside addr = %v, want %v", n.Inside().Addr(), insidePrefix)
	}
	if n.Outside().Addr() != outsidePrefix {
		t.Fatalf("Outside addr = %v, want %v", n.Outside().Addr(), outsidePrefix)
	}

	newPrefix := netip.MustParsePrefix("10.0.0.1/24")
	n.Outside().SetAddr(newPrefix)
	if n.Outside().Addr() != newPrefix {
		t.Fatalf("SetAddr didn't take effect")
	}
}
