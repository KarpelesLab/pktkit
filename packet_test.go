package pktkit

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// ---------- helpers ----------

// makeIPv4 builds a minimal 20-byte IPv4 header (no options) with the given
// fields, followed by payload. Checksum is left zeroed (not needed for parsing).
func makeIPv4(src, dst netip.Addr, proto Protocol, ttl uint8, payload []byte) Packet {
	totalLen := 20 + len(payload)
	p := make(Packet, totalLen)

	p[0] = 0x45 // version=4, IHL=5 (20 bytes)
	binary.BigEndian.PutUint16(p[2:4], uint16(totalLen))
	p[8] = ttl
	p[9] = byte(proto)

	s := src.As4()
	copy(p[12:16], s[:])
	d := dst.As4()
	copy(p[16:20], d[:])

	copy(p[20:], payload)
	return p
}

// makeIPv6 builds a minimal 40-byte IPv6 header followed by payload.
func makeIPv6(src, dst netip.Addr, nextHeader Protocol, hopLimit uint8, payload []byte) Packet {
	p := make(Packet, 40+len(payload))

	p[0] = 0x60 // version=6, traffic class high nibble=0
	binary.BigEndian.PutUint16(p[4:6], uint16(len(payload)))
	p[6] = byte(nextHeader)
	p[7] = hopLimit

	s := src.As16()
	copy(p[8:24], s[:])
	d := dst.As16()
	copy(p[24:40], d[:])

	copy(p[40:], payload)
	return p
}

// ---------- IsValid ----------

func TestPacketIsValid(t *testing.T) {
	tests := []struct {
		name string
		pkt  Packet
		want bool
	}{
		{
			"valid IPv4 (20 bytes)",
			makeIPv4(
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				ProtocolTCP, 64, nil,
			),
			true,
		},
		{
			"valid IPv4 with payload",
			makeIPv4(
				netip.MustParseAddr("192.168.1.1"),
				netip.MustParseAddr("192.168.1.2"),
				ProtocolUDP, 128, []byte("hello"),
			),
			true,
		},
		{
			"valid IPv6 (40 bytes)",
			makeIPv6(
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("::2"),
				ProtocolTCP, 64, nil,
			),
			true,
		},
		{
			"too short for IPv4",
			func() Packet {
				p := make(Packet, 19)
				p[0] = 0x45
				return p
			}(),
			false,
		},
		{
			"too short for IPv6",
			func() Packet {
				p := make(Packet, 39)
				p[0] = 0x60
				return p
			}(),
			false,
		},
		{
			"bad version (3)",
			func() Packet {
				p := make(Packet, 40)
				p[0] = 0x30
				return p
			}(),
			false,
		},
		{"empty", Packet{}, false},
		{"nil", Packet(nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pkt.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- Version ----------

func TestVersion(t *testing.T) {
	v4 := makeIPv4(netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("5.6.7.8"), ProtocolTCP, 64, nil)
	if got := v4.Version(); got != 4 {
		t.Errorf("Version() = %d, want 4", got)
	}

	v6 := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolUDP, 64, nil)
	if got := v6.Version(); got != 6 {
		t.Errorf("Version() = %d, want 6", got)
	}

	empty := Packet{}
	if got := empty.Version(); got != 0 {
		t.Errorf("Version() on empty = %d, want 0", got)
	}
}

// ---------- IPv4 accessors ----------

func TestIPv4HeaderLen(t *testing.T) {
	p := makeIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ProtocolTCP, 64, nil)
	if got := p.IPv4HeaderLen(); got != 20 {
		t.Errorf("IPv4HeaderLen() = %d, want 20", got)
	}

	// IHL = 6 (24 bytes, e.g. with options)
	p2 := make(Packet, 24)
	p2[0] = 0x46
	if got := p2.IPv4HeaderLen(); got != 24 {
		t.Errorf("IPv4HeaderLen() IHL=6 = %d, want 24", got)
	}
}

func TestIPv4TotalLen(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03}
	p := makeIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ProtocolUDP, 64, payload)
	want := uint16(20 + len(payload))
	if got := p.IPv4TotalLen(); got != want {
		t.Errorf("IPv4TotalLen() = %d, want %d", got, want)
	}
}

func TestIPv4TTL(t *testing.T) {
	p := makeIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ProtocolTCP, 255, nil)
	if got := p.IPv4TTL(); got != 255 {
		t.Errorf("IPv4TTL() = %d, want 255", got)
	}
}

func TestIPv4Protocol(t *testing.T) {
	tests := []struct {
		proto Protocol
	}{
		{ProtocolTCP},
		{ProtocolUDP},
		{ProtocolICMP},
	}
	for _, tc := range tests {
		p := makeIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), tc.proto, 64, nil)
		if got := p.IPv4Protocol(); got != tc.proto {
			t.Errorf("IPv4Protocol() = %d, want %d", got, tc.proto)
		}
	}
}

func TestIPv4SrcDstAddr(t *testing.T) {
	src := netip.MustParseAddr("192.168.10.5")
	dst := netip.MustParseAddr("172.16.0.1")
	p := makeIPv4(src, dst, ProtocolTCP, 64, nil)

	if got := p.IPv4SrcAddr(); got != src {
		t.Errorf("IPv4SrcAddr() = %s, want %s", got, src)
	}
	if got := p.IPv4DstAddr(); got != dst {
		t.Errorf("IPv4DstAddr() = %s, want %s", got, dst)
	}
}

func TestIPv4Payload(t *testing.T) {
	payload := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	p := makeIPv4(netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), ProtocolTCP, 64, payload)

	got := p.IPv4Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("IPv4Payload() = %x, want %x", got, payload)
	}
}

func TestIPv4PayloadNil(t *testing.T) {
	// Packet with IHL=0 (invalid)
	p := Packet(make([]byte, 20))
	p[0] = 0x40 // version=4, IHL=0
	if got := p.IPv4Payload(); got != nil {
		t.Errorf("IPv4Payload() with IHL=0 = %x, want nil", got)
	}
}

// ---------- IPv6 accessors ----------

func TestIPv6PayloadLen(t *testing.T) {
	payload := []byte("hello world")
	p := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolTCP, 64, payload)
	want := uint16(len(payload))
	if got := p.IPv6PayloadLen(); got != want {
		t.Errorf("IPv6PayloadLen() = %d, want %d", got, want)
	}
}

func TestIPv6NextHeader(t *testing.T) {
	p := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolUDP, 64, nil)
	if got := p.IPv6NextHeader(); got != ProtocolUDP {
		t.Errorf("IPv6NextHeader() = %d, want %d", got, ProtocolUDP)
	}
}

func TestIPv6HopLimit(t *testing.T) {
	p := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolTCP, 128, nil)
	if got := p.IPv6HopLimit(); got != 128 {
		t.Errorf("IPv6HopLimit() = %d, want 128", got)
	}
}

func TestIPv6SrcDstAddr(t *testing.T) {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	p := makeIPv6(src, dst, ProtocolTCP, 64, nil)

	if got := p.IPv6SrcAddr(); got != src {
		t.Errorf("IPv6SrcAddr() = %s, want %s", got, src)
	}
	if got := p.IPv6DstAddr(); got != dst {
		t.Errorf("IPv6DstAddr() = %s, want %s", got, dst)
	}
}

func TestIPv6Payload(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	p := makeIPv6(netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2"), ProtocolUDP, 64, payload)
	got := p.IPv6Payload()
	if !bytes.Equal(got, payload) {
		t.Errorf("IPv6Payload() = %x, want %x", got, payload)
	}
}

func TestIPv6PayloadTooShort(t *testing.T) {
	p := Packet(make([]byte, 30))
	p[0] = 0x60
	if got := p.IPv6Payload(); got != nil {
		t.Errorf("IPv6Payload() on short packet = %x, want nil", got)
	}
}

// ---------- Version-independent accessors ----------

func TestSrcAddr(t *testing.T) {
	v4Src := netip.MustParseAddr("10.10.10.10")
	v4 := makeIPv4(v4Src, netip.MustParseAddr("10.10.10.20"), ProtocolTCP, 64, nil)
	if got := v4.SrcAddr(); got != v4Src {
		t.Errorf("SrcAddr() IPv4 = %s, want %s", got, v4Src)
	}

	v6Src := netip.MustParseAddr("fd00::1")
	v6 := makeIPv6(v6Src, netip.MustParseAddr("fd00::2"), ProtocolTCP, 64, nil)
	if got := v6.SrcAddr(); got != v6Src {
		t.Errorf("SrcAddr() IPv6 = %s, want %s", got, v6Src)
	}

	bad := Packet{0x30} // version 3
	if got := bad.SrcAddr(); got.IsValid() {
		t.Errorf("SrcAddr() bad version = %s, want invalid", got)
	}
}

func TestDstAddr(t *testing.T) {
	v4Dst := netip.MustParseAddr("10.10.10.20")
	v4 := makeIPv4(netip.MustParseAddr("10.10.10.10"), v4Dst, ProtocolTCP, 64, nil)
	if got := v4.DstAddr(); got != v4Dst {
		t.Errorf("DstAddr() IPv4 = %s, want %s", got, v4Dst)
	}

	v6Dst := netip.MustParseAddr("fd00::2")
	v6 := makeIPv6(netip.MustParseAddr("fd00::1"), v6Dst, ProtocolTCP, 64, nil)
	if got := v6.DstAddr(); got != v6Dst {
		t.Errorf("DstAddr() IPv6 = %s, want %s", got, v6Dst)
	}
}

func TestIPProtocol(t *testing.T) {
	v4 := makeIPv4(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), ProtocolUDP, 64, nil)
	if got := v4.IPProtocol(); got != ProtocolUDP {
		t.Errorf("IPProtocol() IPv4 = %d, want %d", got, ProtocolUDP)
	}

	v6 := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolICMPv6, 64, nil)
	if got := v6.IPProtocol(); got != ProtocolICMPv6 {
		t.Errorf("IPProtocol() IPv6 = %d, want %d", got, ProtocolICMPv6)
	}

	bad := Packet{0x30}
	if got := bad.IPProtocol(); got != 0 {
		t.Errorf("IPProtocol() bad version = %d, want 0", got)
	}
}

func TestPacketPayload(t *testing.T) {
	v4Data := []byte{0xAA, 0xBB}
	v4 := makeIPv4(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), ProtocolTCP, 64, v4Data)
	if got := v4.Payload(); !bytes.Equal(got, v4Data) {
		t.Errorf("Payload() IPv4 = %x, want %x", got, v4Data)
	}

	v6Data := []byte{0xCC, 0xDD, 0xEE}
	v6 := makeIPv6(netip.MustParseAddr("::1"), netip.MustParseAddr("::2"), ProtocolUDP, 64, v6Data)
	if got := v6.Payload(); !bytes.Equal(got, v6Data) {
		t.Errorf("Payload() IPv6 = %x, want %x", got, v6Data)
	}

	bad := Packet{0x30}
	if got := bad.Payload(); got != nil {
		t.Errorf("Payload() bad version = %x, want nil", got)
	}
}

// ---------- IsBroadcast ----------

func TestPacketIsBroadcast(t *testing.T) {
	bcast := makeIPv4(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("255.255.255.255"),
		ProtocolUDP, 64, nil,
	)
	if !bcast.IsBroadcast() {
		t.Error("IsBroadcast() = false for 255.255.255.255")
	}

	unicast := makeIPv4(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		ProtocolTCP, 64, nil,
	)
	if unicast.IsBroadcast() {
		t.Error("IsBroadcast() = true for unicast IPv4")
	}

	// IPv6 never broadcast.
	v6 := makeIPv6(
		netip.MustParseAddr("::1"),
		netip.MustParseAddr("ff02::1"),
		ProtocolICMPv6, 64, nil,
	)
	if v6.IsBroadcast() {
		t.Error("IsBroadcast() = true for IPv6 (should always be false)")
	}
}

// ---------- IsMulticast ----------

func TestPacketIsMulticast(t *testing.T) {
	tests := []struct {
		name string
		pkt  Packet
		want bool
	}{
		{
			"IPv4 multicast 224.0.0.1",
			makeIPv4(
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("224.0.0.1"),
				ProtocolUDP, 64, nil,
			),
			true,
		},
		{
			"IPv4 multicast 239.255.255.255",
			makeIPv4(
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("239.255.255.255"),
				ProtocolUDP, 64, nil,
			),
			true,
		},
		{
			"IPv4 unicast",
			makeIPv4(
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("10.0.0.2"),
				ProtocolTCP, 64, nil,
			),
			false,
		},
		{
			"IPv4 broadcast (not multicast range)",
			makeIPv4(
				netip.MustParseAddr("10.0.0.1"),
				netip.MustParseAddr("255.255.255.255"),
				ProtocolUDP, 64, nil,
			),
			false, // 255 & 0xF0 == 0xF0, not 0xE0
		},
		{
			"IPv6 multicast ff02::1",
			makeIPv6(
				netip.MustParseAddr("fe80::1"),
				netip.MustParseAddr("ff02::1"),
				ProtocolICMPv6, 64, nil,
			),
			true,
		},
		{
			"IPv6 unicast",
			makeIPv6(
				netip.MustParseAddr("::1"),
				netip.MustParseAddr("2001:db8::1"),
				ProtocolTCP, 64, nil,
			),
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.pkt.IsMulticast(); got != tc.want {
				t.Errorf("IsMulticast() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- SetIPv4SrcAddr / SetIPv4DstAddr ----------

func TestSetIPv4SrcAddr(t *testing.T) {
	p := makeIPv4(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		ProtocolTCP, 64, nil,
	)
	newSrc := netip.MustParseAddr("192.168.1.100")
	p.SetIPv4SrcAddr(newSrc)

	if got := p.IPv4SrcAddr(); got != newSrc {
		t.Errorf("after SetIPv4SrcAddr, IPv4SrcAddr() = %s, want %s", got, newSrc)
	}
	// Dst must be untouched.
	if got := p.IPv4DstAddr(); got != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("SetIPv4SrcAddr mutated dst: got %s", got)
	}
}

func TestSetIPv4DstAddr(t *testing.T) {
	p := makeIPv4(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		ProtocolTCP, 64, nil,
	)
	newDst := netip.MustParseAddr("172.16.0.50")
	p.SetIPv4DstAddr(newDst)

	if got := p.IPv4DstAddr(); got != newDst {
		t.Errorf("after SetIPv4DstAddr, IPv4DstAddr() = %s, want %s", got, newDst)
	}
	// Src must be untouched.
	if got := p.IPv4SrcAddr(); got != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("SetIPv4DstAddr mutated src: got %s", got)
	}
}

// ---------- Edge cases for short packets ----------

func TestIPv4AccessorsOnShortPacket(t *testing.T) {
	p := Packet(make([]byte, 3))
	p[0] = 0x45

	if got := p.IPv4TotalLen(); got != 0 {
		t.Errorf("IPv4TotalLen() on 3-byte packet = %d, want 0", got)
	}
	if got := p.IPv4TTL(); got != 0 {
		t.Errorf("IPv4TTL() on 3-byte packet = %d, want 0", got)
	}
	if got := p.IPv4Protocol(); got != 0 {
		t.Errorf("IPv4Protocol() on 3-byte packet = %d, want 0", got)
	}
	if got := p.IPv4SrcAddr(); got.IsValid() {
		t.Errorf("IPv4SrcAddr() on 3-byte packet = %s, want invalid", got)
	}
	if got := p.IPv4DstAddr(); got.IsValid() {
		t.Errorf("IPv4DstAddr() on 3-byte packet = %s, want invalid", got)
	}
}

func TestIPv6AccessorsOnShortPacket(t *testing.T) {
	p := Packet(make([]byte, 5))
	p[0] = 0x60

	if got := p.IPv6PayloadLen(); got != 0 {
		t.Errorf("IPv6PayloadLen() on 5-byte packet = %d, want 0", got)
	}
	if got := p.IPv6NextHeader(); got != 0 {
		t.Errorf("IPv6NextHeader() on 5-byte packet = %d, want 0", got)
	}
	if got := p.IPv6HopLimit(); got != 0 {
		t.Errorf("IPv6HopLimit() on 5-byte packet = %d, want 0", got)
	}
	if got := p.IPv6SrcAddr(); got.IsValid() {
		t.Errorf("IPv6SrcAddr() on 5-byte packet = %s, want invalid", got)
	}
	if got := p.IPv6DstAddr(); got.IsValid() {
		t.Errorf("IPv6DstAddr() on 5-byte packet = %s, want invalid", got)
	}
}
