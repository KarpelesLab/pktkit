package pktkit

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"
)

// --- helpers ---

// buildTestFrame returns a 1514-byte Ethernet frame (14-byte header + 1500-byte IPv4 TCP payload).
func buildTestFrame() Frame {
	dstMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	payload := make([]byte, 1500)
	// Minimal IPv4 header
	payload[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(payload[2:4], 1500)
	payload[8] = 64 // TTL
	payload[9] = 6  // TCP
	copy(payload[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(payload[16:20], net.IPv4(10, 0, 0, 2).To4())
	return NewFrame(dstMAC, srcMAC, EtherTypeIPv4, payload)
}

// buildTestIPv4Packet returns a 1500-byte TCP/IPv4 packet.
func buildTestIPv4Packet() Packet {
	pkt := make(Packet, 1500)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 1500)
	pkt[8] = 64
	pkt[9] = 6 // TCP
	copy(pkt[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(pkt[16:20], net.IPv4(192, 168, 1, 1).To4())
	// TCP header at offset 20
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // src port
	binary.BigEndian.PutUint16(pkt[22:24], 80)    // dst port
	pkt[32] = 0x50                                // data offset = 5 (20 bytes)
	return pkt
}

// buildTestIPv6Packet returns an IPv6 TCP packet (40-byte IPv6 + 20-byte TCP + 1400-byte payload).
func buildTestIPv6Packet() Packet {
	pkt := make(Packet, 1460)
	pkt[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(pkt[4:6], 1420)
	pkt[6] = 6  // next header: TCP
	pkt[7] = 64 // hop limit
	// src: 2001:db8::1
	pkt[8] = 0x20
	pkt[9] = 0x01
	pkt[10] = 0x0d
	pkt[11] = 0xb8
	pkt[23] = 0x01
	// dst: 2001:db8::2
	pkt[24] = 0x20
	pkt[25] = 0x01
	pkt[26] = 0x0d
	pkt[27] = 0xb8
	pkt[39] = 0x02
	// TCP header at offset 40
	binary.BigEndian.PutUint16(pkt[40:42], 12345)
	binary.BigEndian.PutUint16(pkt[42:44], 443)
	pkt[52] = 0x50
	return pkt
}

// --- Frame benchmarks ---

func BenchmarkFrameAccessors(b *testing.B) {
	f := buildTestFrame()
	b.ReportAllocs()
	b.SetBytes(int64(len(f)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = f.DstMAC()
		_ = f.SrcMAC()
		_ = f.EtherType()
		_ = f.Payload()
		_ = f.IsBroadcast()
		_ = f.IsMulticast()
		_ = f.IsValid()
		_ = f.HeaderLen()
	}
}

func BenchmarkFrameSetMAC(b *testing.B) {
	f := buildTestFrame()
	mac := net.HardwareAddr{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.SetDstMAC(mac)
		f.SetSrcMAC(mac)
	}
}

func BenchmarkNewFrame(b *testing.B) {
	dstMAC := net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srcMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	payload := make([]byte, 1500)
	b.ReportAllocs()
	b.SetBytes(int64(14 + len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewFrame(dstMAC, srcMAC, EtherTypeIPv4, payload)
	}
}

// --- Packet benchmarks ---

func BenchmarkPacketIPv4Accessors(b *testing.B) {
	pkt := buildTestIPv4Packet()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.IsValid()
		_ = pkt.Version()
		_ = pkt.IPv4SrcAddr()
		_ = pkt.IPv4DstAddr()
		_ = pkt.IPv4Protocol()
		_ = pkt.IPv4Payload()
		_ = pkt.IPv4HeaderLen()
		_ = pkt.IPv4TotalLen()
		_ = pkt.IsBroadcast()
		_ = pkt.IsMulticast()
	}
}

func BenchmarkPacketIPv6Accessors(b *testing.B) {
	pkt := buildTestIPv6Packet()
	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pkt.IsValid()
		_ = pkt.Version()
		_ = pkt.IPv6SrcAddr()
		_ = pkt.IPv6DstAddr()
		_ = pkt.IPv6NextHeader()
		_ = pkt.IPv6Payload()
		_ = pkt.IPv6PayloadLen()
	}
}

// --- Checksum benchmarks ---

func BenchmarkPseudoHeaderChecksumIPv4(b *testing.B) {
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PseudoHeaderChecksum(ProtocolTCP, src, dst, 1460)
	}
}

func BenchmarkPseudoHeaderChecksumIPv6(b *testing.B) {
	src := netip.MustParseAddr("2001:db8::1")
	dst := netip.MustParseAddr("2001:db8::2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = PseudoHeaderChecksum(ProtocolTCP, src, dst, 1460)
	}
}

// --- L2Hub forwarding benchmark ---

func BenchmarkL2HubForward(b *testing.B) {
	hub := NewL2Hub()

	macs := []net.HardwareAddr{
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x03},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x04},
	}
	pipes := make([]*PipeL2, 4)
	handles := make([]*L2HubHandle, 4)
	for i := range 4 {
		pipes[i] = NewPipeL2(macs[i])
		handles[i] = hub.Connect(pipes[i])
	}
	defer func() {
		for _, h := range handles {
			h.Close()
		}
	}()

	// Override all handlers with sinks to prevent re-forwarding loops.
	sink := func(Frame) error { return nil }
	for _, p := range pipes {
		p.SetHandler(sink)
	}

	// Pre-learn MACs: directly populate the MAC table.
	for i, h := range handles {
		hub.macTable.Store([6]byte(macs[i]), macEntry{
			portID:  h.id,
			expires: time.Now().Add(macAgingDuration).UnixNano(),
		})
	}

	// Build a unicast frame from port 0 → port 1 (known destination).
	frame := NewFrame(macs[1], macs[0], EtherTypeIPv4, make([]byte, 1500))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hub.forward(frame, handles[0].id)
	}
}

func BenchmarkL2HubForwardParallel(b *testing.B) {
	hub := NewL2Hub()
	macs := []net.HardwareAddr{
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
		{0x02, 0x00, 0x00, 0x00, 0x00, 0x02},
	}
	p0 := NewPipeL2(macs[0])
	p1 := NewPipeL2(macs[1])
	h0 := hub.Connect(p0)
	h1 := hub.Connect(p1)
	defer h0.Close()
	defer h1.Close()

	// Override handlers with sinks.
	sink := func(Frame) error { return nil }
	p0.SetHandler(sink)
	p1.SetHandler(sink)

	// Pre-learn MACs directly.
	hub.macTable.Store([6]byte(macs[0]), macEntry{portID: h0.id, expires: time.Now().Add(macAgingDuration).UnixNano()})
	hub.macTable.Store([6]byte(macs[1]), macEntry{portID: h1.id, expires: time.Now().Add(macAgingDuration).UnixNano()})

	frame := NewFrame(macs[1], macs[0], EtherTypeIPv4, make([]byte, 1500))

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			hub.forward(frame, h0.id)
		}
	})
}

// --- L3Hub routing benchmark ---

func BenchmarkL3HubRoute(b *testing.B) {
	hub := NewL3Hub()

	devs := make([]*PipeL3, 4)
	handles := make([]*L3HubHandle, 4)
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.3.0/24"),
		netip.MustParsePrefix("10.0.4.0/24"),
	}
	for i := range 4 {
		devs[i] = NewPipeL3(prefixes[i])
		handles[i] = hub.Connect(devs[i])
	}
	defer func() {
		for _, h := range handles {
			h.Close()
		}
	}()

	// Override handlers with sinks to prevent re-forwarding.
	sink := func(Packet) error { return nil }
	for _, d := range devs {
		d.SetHandler(sink)
	}

	// Build a packet from 10.0.1.1 → 10.0.2.1 (matches port 1).
	pkt := make(Packet, 1500)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 1500)
	pkt[9] = 6
	copy(pkt[12:16], net.IPv4(10, 0, 1, 1).To4())
	copy(pkt[16:20], net.IPv4(10, 0, 2, 1).To4())

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Call route directly to avoid re-forwarding through handlers.
		hub.route(pkt, handles[0].id)
	}
}

// --- L2Adapter benchmarks ---

func BenchmarkL2AdapterIncoming(b *testing.B) {
	l3dev := NewPipeL3(netip.MustParsePrefix("10.0.0.1/24"))
	adapter := NewL2Adapter(l3dev, net.HardwareAddr{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE})
	defer adapter.Close()

	// Build an Ethernet frame destined for this adapter's MAC.
	ipPayload := make([]byte, 1500)
	ipPayload[0] = 0x45
	binary.BigEndian.PutUint16(ipPayload[2:4], 1500)
	ipPayload[9] = 6
	copy(ipPayload[12:16], net.IPv4(10, 0, 0, 2).To4())
	copy(ipPayload[16:20], net.IPv4(10, 0, 0, 1).To4())
	// TCP header
	binary.BigEndian.PutUint16(ipPayload[20:22], 12345)
	binary.BigEndian.PutUint16(ipPayload[22:24], 80)
	ipPayload[32] = 0x50

	frame := NewFrame(adapter.mac, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}, EtherTypeIPv4, ipPayload)

	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		adapter.Send(frame)
	}
}

func BenchmarkL2AdapterOutgoing(b *testing.B) {
	l3dev := NewPipeL3(netip.MustParsePrefix("10.0.0.1/24"))
	adapter := NewL2Adapter(l3dev, net.HardwareAddr{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE})
	defer adapter.Close()

	// Pre-populate ARP table so we don't trigger ARP resolution.
	dstMAC := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	adapter.arp.Set(netip.MustParseAddr("10.0.0.2"), dstMAC, arpDefaultTTL)

	// Set up L2 handler (sink).
	adapter.SetHandler(func(f Frame) error { return nil })

	// Build a unicast IPv4 packet.
	pkt := make(Packet, 1500)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 1500)
	pkt[9] = 6
	copy(pkt[12:16], net.IPv4(10, 0, 0, 1).To4())
	copy(pkt[16:20], net.IPv4(10, 0, 0, 2).To4())

	// Warm up the pool.
	for i := 0; i < 100; i++ {
		l3dev.Inject(pkt)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		l3dev.Inject(pkt)
	}
}

// --- ARP table benchmark ---

func BenchmarkARPLookup(b *testing.B) {
	table := newARPTable()
	ip := netip.MustParseAddr("10.0.0.1")
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	table.Set(ip, mac, arpDefaultTTL)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Lookup(ip)
	}
}

func BenchmarkARPLookupParallel(b *testing.B) {
	table := newARPTable()
	ip := netip.MustParseAddr("10.0.0.1")
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	table.Set(ip, mac, arpDefaultTTL)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = table.Lookup(ip)
		}
	})
}

// --- NDP table benchmark ---

func BenchmarkNDPLookup(b *testing.B) {
	table := newNDPTable()
	ip := netip.MustParseAddr("2001:db8::1")
	mac := net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	table.Set(ip, mac, ndpDefaultTTL)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = table.Lookup(ip)
	}
}
