package nat

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// buildTCPPacket builds a TCP/IPv4 packet with the given addresses and ports.
func buildTCPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payloadSize int) pktkit.Packet {
	ihl := 20
	tcpHdr := 20
	totalLen := ihl + tcpHdr + payloadSize
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = protoTCP
	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	// IP checksum
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:ihl]))

	// TCP header
	tcp := pkt[ihl:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(tcp[8:12], 2000) // ack
	tcp[12] = 0x50                              // data offset = 5
	tcp[13] = 0x10                              // ACK flag
	binary.BigEndian.PutUint16(tcp[14:16], 65535)

	// TCP checksum
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolTCP, srcIP, dstIP, uint16(tcpHdr+payloadSize))
	dataCsum := pktkit.Checksum(tcp)
	sum := uint32(^phCsum) + uint32(^dataCsum)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcp[16:18], ^uint16(sum))

	return pkt
}

func BenchmarkNATOutboundTCP(b *testing.B) {
	insidePrefix := netip.MustParsePrefix("10.0.0.1/24")
	outsidePrefix := netip.MustParsePrefix("192.168.1.1/24")
	n := New(insidePrefix, outsidePrefix)
	defer n.Close()

	// Set up a sink handler on the outside so packets are consumed.
	n.Outside().SetHandler(func(pkt pktkit.Packet) error { return nil })

	// Build a TCP packet from inside client → external destination.
	pkt := buildTCPPacket(
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("8.8.8.8"),
		12345, 80, 1400,
	)

	// Warm up: create the mapping.
	n.Inside().Send(pkt)

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Inside().Send(pkt)
	}
}

func BenchmarkNATInboundTCP(b *testing.B) {
	insidePrefix := netip.MustParsePrefix("10.0.0.1/24")
	outsidePrefix := netip.MustParsePrefix("192.168.1.1/24")
	n := New(insidePrefix, outsidePrefix)
	defer n.Close()

	// Sink on inside.
	n.Inside().SetHandler(func(pkt pktkit.Packet) error { return nil })
	// Sink on outside (for outbound warmup).
	n.Outside().SetHandler(func(pkt pktkit.Packet) error { return nil })

	// Create a mapping by sending an outbound packet first.
	outPkt := buildTCPPacket(
		netip.MustParseAddr("10.0.0.100"),
		netip.MustParseAddr("8.8.8.8"),
		12345, 80, 100,
	)
	n.Inside().Send(outPkt)

	// Now find the allocated outside port by inspecting the mapping.
	k := natKey{proto: protoTCP, ip: netip.MustParseAddr("10.0.0.100"), port: 12345}
	n.mu.Lock()
	m := n.mappings[k]
	outsidePort := m.outsidePort
	n.mu.Unlock()

	// Build an inbound packet from 8.8.8.8:80 → outsideIP:outsidePort.
	inPkt := buildTCPPacket(
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.168.1.1"),
		80, outsidePort, 1400,
	)

	b.ReportAllocs()
	b.SetBytes(int64(len(inPkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Outside().Send(inPkt)
	}
}

func BenchmarkNATMappingLookup(b *testing.B) {
	insidePrefix := netip.MustParsePrefix("10.0.0.1/24")
	outsidePrefix := netip.MustParsePrefix("192.168.1.1/24")
	n := New(insidePrefix, outsidePrefix)
	defer n.Close()

	n.Outside().SetHandler(func(pkt pktkit.Packet) error { return nil })

	// Create 100 mappings to have a realistic map size.
	for i := 0; i < 100; i++ {
		pkt := buildTCPPacket(
			netip.MustParseAddr("10.0.0.100"),
			netip.MustParseAddr("8.8.8.8"),
			uint16(10000+i), 80, 20,
		)
		n.Inside().Send(pkt)
	}

	// Benchmark lookup of an existing mapping.
	k := natKey{proto: protoTCP, ip: netip.MustParseAddr("10.0.0.100"), port: 10050}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.mu.Lock()
		m := n.mappings[k]
		if m != nil {
			_ = m.outsidePort
		}
		n.mu.Unlock()
	}
}

func BenchmarkNATMappingLookupParallel(b *testing.B) {
	insidePrefix := netip.MustParsePrefix("10.0.0.1/24")
	outsidePrefix := netip.MustParsePrefix("192.168.1.1/24")
	n := New(insidePrefix, outsidePrefix)
	defer n.Close()

	n.Outside().SetHandler(func(pkt pktkit.Packet) error { return nil })

	for i := 0; i < 100; i++ {
		pkt := buildTCPPacket(
			netip.MustParseAddr("10.0.0.100"),
			netip.MustParseAddr("8.8.8.8"),
			uint16(10000+i), 80, 20,
		)
		n.Inside().Send(pkt)
	}

	k := natKey{proto: protoTCP, ip: netip.MustParseAddr("10.0.0.100"), port: 10050}

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n.mu.Lock()
			m := n.mappings[k]
			if m != nil {
				_ = m.outsidePort
			}
			n.mu.Unlock()
		}
	})
}

// BenchmarkDefragProcess benchmarks unfragmented packet pass-through.
func BenchmarkDefragProcess(b *testing.B) {
	d := newDefragger()
	defer d.Close()

	pkt := buildTCPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345, 80, 1400,
	)
	// Clear fragment flags (unfragmented).
	binary.BigEndian.PutUint16(pkt[6:8], 0)

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Process(pkt)
	}
}

// buildUDPPacket builds a UDP/IPv4 packet.
func buildUDPPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payloadSize int) pktkit.Packet {
	ihl := 20
	udpHdr := 8
	totalLen := ihl + udpHdr + payloadSize
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = protoUDP
	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:ihl]))

	udp := pkt[ihl:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHdr+payloadSize))
	// UDP checksum = 0 (optional for IPv4)
	return pkt
}

func BenchmarkNATOutboundUDP(b *testing.B) {
	n := New(netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("192.168.1.1/24"))
	defer n.Close()
	n.Outside().SetHandler(func(pkt pktkit.Packet) error { return nil })

	pkt := buildUDPPacket(netip.MustParseAddr("10.0.0.100"), netip.MustParseAddr("8.8.8.8"), 5000, 53, 100)
	n.Inside().Send(pkt) // warmup

	b.ReportAllocs()
	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n.Inside().Send(pkt)
	}
}

// --- Checksum utility benchmarks ---

func BenchmarkUpdateIPChecksum(b *testing.B) {
	pkt := buildTCPPacket(
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("10.0.0.2"),
		12345, 80, 1400,
	)
	oldSrc := [4]byte{10, 0, 0, 1}
	newSrc := [4]byte{192, 168, 1, 1}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		updateIPChecksum(pkt, oldSrc, newSrc)
		// Reverse to keep the packet valid for next iteration.
		updateIPChecksum(pkt, newSrc, oldSrc)
	}
}

// emptyHandler is a reusable no-op handler to avoid capturing closures.
var emptyHandler = func(pkt pktkit.Packet) error { return nil }

func init() {
	_ = net.IPv4(0, 0, 0, 0) // ensure net is used
}
