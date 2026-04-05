package nat

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// recorder captures packets sent to it.
type recorder struct {
	mu       sync.Mutex
	received []pktkit.Packet
	addr     netip.Prefix
}

func (r *recorder) SetHandler(func(pktkit.Packet) error) {}
func (r *recorder) Send(pkt pktkit.Packet) error {
	cp := make(pktkit.Packet, len(pkt))
	copy(cp, pkt)
	r.mu.Lock()
	r.received = append(r.received, cp)
	r.mu.Unlock()
	return nil
}
func (r *recorder) Addr() netip.Prefix           { return r.addr }
func (r *recorder) SetAddr(p netip.Prefix) error { r.addr = p; return nil }
func (r *recorder) Close() error                 { return nil }

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.received)
}

func (r *recorder) last() pktkit.Packet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received[len(r.received)-1]
}

// makeIPv4TCP builds a minimal IPv4+TCP packet.
func makeIPv4TCP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags byte) pktkit.Packet {
	ihl := 20
	tcpHL := 20
	totalLen := ihl + tcpHL
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
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))
	// TCP header
	binary.BigEndian.PutUint16(pkt[ihl:ihl+2], srcPort)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], dstPort)
	pkt[ihl+12] = 5 << 4 // data offset
	pkt[ihl+13] = flags
	binary.BigEndian.PutUint16(pkt[ihl+14:ihl+16], 65535) // window
	// TCP checksum (pseudo-header + header)
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], 0)
	binary.BigEndian.PutUint16(pkt[ihl+16:ihl+18], tcpChecksum(pkt))
	return pkt
}

// makeIPv4UDP builds a minimal IPv4+UDP packet with payload.
func makeIPv4UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) pktkit.Packet {
	ihl := 20
	udpLen := 8 + len(payload)
	totalLen := ihl + udpLen
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = protoUDP
	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))
	// UDP
	binary.BigEndian.PutUint16(pkt[ihl:ihl+2], srcPort)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], dstPort)
	binary.BigEndian.PutUint16(pkt[ihl+4:ihl+6], uint16(udpLen))
	copy(pkt[ihl+8:], payload)
	// UDP checksum = 0 (optional for IPv4)
	return pkt
}

// makeICMPEcho builds an IPv4 ICMP echo request.
func makeICMPEcho(srcIP, dstIP netip.Addr, id, seq uint16) pktkit.Packet {
	ihl := 20
	icmpLen := 8
	totalLen := ihl + icmpLen
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = protoICMP
	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))
	// ICMP
	pkt[ihl] = 8 // echo request
	binary.BigEndian.PutUint16(pkt[ihl+4:ihl+6], id)
	binary.BigEndian.PutUint16(pkt[ihl+6:ihl+8], seq)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], 0)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], pktkit.Checksum(pkt[ihl:]))
	return pkt
}

// makeICMPEchoReply builds an ICMP echo reply.
func makeICMPEchoReply(srcIP, dstIP netip.Addr, id, seq uint16) pktkit.Packet {
	pkt := makeICMPEcho(srcIP, dstIP, id, seq)
	pkt[20] = 0 // type = echo reply
	binary.BigEndian.PutUint16(pkt[22:24], 0)
	binary.BigEndian.PutUint16(pkt[22:24], pktkit.Checksum(pkt[20:]))
	return pkt
}

// makeICMPUnreachable builds an ICMP Destination Unreachable containing
// the first 28 bytes (IP header + 8 bytes) of the triggering packet.
func makeICMPUnreachable(srcIP, dstIP netip.Addr, code byte, trigger pktkit.Packet) pktkit.Packet {
	ihl := 20
	// ICMP: type(1)+code(1)+csum(2)+unused(4) + embedded header (28 bytes min)
	embLen := 28
	if len(trigger) < embLen {
		embLen = len(trigger)
	}
	icmpLen := 8 + embLen
	totalLen := ihl + icmpLen
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64
	pkt[9] = protoICMP
	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))
	// ICMP
	pkt[ihl] = 3 // Destination Unreachable
	pkt[ihl+1] = code
	copy(pkt[ihl+8:], trigger[:embLen])
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], 0)
	binary.BigEndian.PutUint16(pkt[ihl+2:ihl+4], pktkit.Checksum(pkt[ihl:]))
	return pkt
}

func tcpChecksum(pkt pktkit.Packet) uint16 {
	ihl := int(pkt[0]&0x0F) * 4
	tcp := pkt[ihl:]
	// Pseudo-header
	var sum uint32
	for i := 12; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	sum += uint32(protoTCP)
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	if len(tcp)&1 != 0 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func verifyIPChecksum(t *testing.T, pkt pktkit.Packet) {
	t.Helper()
	if pktkit.Checksum(pkt[:20]) != 0 {
		t.Error("IP header checksum invalid")
	}
}

// --- Tests ---

func TestNAT_TCP_Outbound(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Outside(), outside)

	// Client sends TCP SYN from 10.0.0.2:5000 → 8.8.8.8:80
	pkt := makeIPv4TCP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		5000, 80, 0x02, // SYN
	)
	n.Inside().Send(pkt)

	if outside.count() != 1 {
		t.Fatalf("expected 1 outbound packet, got %d", outside.count())
	}

	out := outside.last()
	// Source IP should be rewritten to outside IP.
	srcIP := netip.AddrFrom4([4]byte(out[12:16]))
	if srcIP != netip.MustParseAddr("192.168.1.100") {
		t.Errorf("src IP = %s, want 192.168.1.100", srcIP)
	}
	// Dst IP unchanged.
	dstIP := netip.AddrFrom4([4]byte(out[16:20]))
	if dstIP != netip.MustParseAddr("8.8.8.8") {
		t.Errorf("dst IP = %s, want 8.8.8.8", dstIP)
	}
	// Source port should be remapped.
	srcPort := binary.BigEndian.Uint16(out[20:22])
	if srcPort < natPortMin || srcPort > natPortMax {
		t.Errorf("src port = %d, want in [%d,%d]", srcPort, natPortMin, natPortMax)
	}
	// Dst port unchanged.
	dstPort := binary.BigEndian.Uint16(out[22:24])
	if dstPort != 80 {
		t.Errorf("dst port = %d, want 80", dstPort)
	}
	verifyIPChecksum(t, out)
}

func TestNAT_TCP_Roundtrip(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	inside := &recorder{addr: netip.MustParsePrefix("10.0.0.2/24")}
	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Inside(), inside)
	pktkit.ConnectL3(n.Outside(), outside)

	// Outbound SYN
	syn := makeIPv4TCP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		5000, 80, 0x02,
	)
	n.Inside().Send(syn)

	if outside.count() != 1 {
		t.Fatal("no outbound packet")
	}
	outPkt := outside.last()
	mappedPort := binary.BigEndian.Uint16(outPkt[20:22])

	// Inbound SYN-ACK from 8.8.8.8:80 → 192.168.1.100:mappedPort
	synack := makeIPv4TCP(
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.168.1.100"),
		80, mappedPort, 0x12, // SYN+ACK
	)
	n.Outside().Send(synack)

	if inside.count() != 1 {
		t.Fatalf("expected 1 inbound packet, got %d", inside.count())
	}

	inPkt := inside.last()
	// Dst should be restored to original private IP.
	dstIP := netip.AddrFrom4([4]byte(inPkt[16:20]))
	if dstIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("dst IP = %s, want 10.0.0.2", dstIP)
	}
	dstPort := binary.BigEndian.Uint16(inPkt[22:24])
	if dstPort != 5000 {
		t.Errorf("dst port = %d, want 5000", dstPort)
	}
	verifyIPChecksum(t, inPkt)
}

func TestNAT_UDP(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	inside := &recorder{addr: netip.MustParsePrefix("10.0.0.2/24")}
	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Inside(), inside)
	pktkit.ConnectL3(n.Outside(), outside)

	// Outbound DNS query
	dns := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("1.1.1.1"),
		12345, 53, []byte("dns-query"),
	)
	n.Inside().Send(dns)

	if outside.count() != 1 {
		t.Fatal("no outbound UDP")
	}
	outPkt := outside.last()
	mappedPort := binary.BigEndian.Uint16(outPkt[20:22])
	verifyIPChecksum(t, outPkt)

	// Inbound DNS response
	resp := makeIPv4UDP(
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("192.168.1.100"),
		53, mappedPort, []byte("dns-resp"),
	)
	n.Outside().Send(resp)

	if inside.count() != 1 {
		t.Fatal("no inbound UDP")
	}
	inPkt := inside.last()
	dstIP := netip.AddrFrom4([4]byte(inPkt[16:20]))
	if dstIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("dst IP = %s, want 10.0.0.2", dstIP)
	}
	dstPort := binary.BigEndian.Uint16(inPkt[22:24])
	if dstPort != 12345 {
		t.Errorf("dst port = %d, want 12345", dstPort)
	}
}

func TestNAT_ICMP_Echo(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	inside := &recorder{addr: netip.MustParsePrefix("10.0.0.2/24")}
	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Inside(), inside)
	pktkit.ConnectL3(n.Outside(), outside)

	// Outbound echo request
	ping := makeICMPEcho(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		1234, 1,
	)
	n.Inside().Send(ping)

	if outside.count() != 1 {
		t.Fatal("no outbound ICMP")
	}
	outPkt := outside.last()
	mappedID := binary.BigEndian.Uint16(outPkt[24:26])
	verifyIPChecksum(t, outPkt)

	// Inbound echo reply
	reply := makeICMPEchoReply(
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.168.1.100"),
		mappedID, 1,
	)
	n.Outside().Send(reply)

	if inside.count() != 1 {
		t.Fatal("no inbound ICMP reply")
	}
	inPkt := inside.last()
	dstIP := netip.AddrFrom4([4]byte(inPkt[16:20]))
	if dstIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("dst IP = %s, want 10.0.0.2", dstIP)
	}
	restoredID := binary.BigEndian.Uint16(inPkt[24:26])
	if restoredID != 1234 {
		t.Errorf("ICMP id = %d, want 1234", restoredID)
	}
}

func TestNAT_ICMP_Error(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	inside := &recorder{addr: netip.MustParsePrefix("10.0.0.2/24")}
	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Inside(), inside)
	pktkit.ConnectL3(n.Outside(), outside)

	// First, establish a TCP mapping.
	syn := makeIPv4TCP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("8.8.8.8"),
		5000, 80, 0x02,
	)
	n.Inside().Send(syn)
	if outside.count() != 1 {
		t.Fatal("no outbound SYN")
	}
	nattedSyn := outside.last()

	// Remote sends ICMP Destination Unreachable (port unreachable) with
	// the NATted SYN packet embedded.
	icmpErr := makeICMPUnreachable(
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.168.1.100"),
		3, // port unreachable
		nattedSyn,
	)
	n.Outside().Send(icmpErr)

	if inside.count() != 1 {
		t.Fatalf("expected 1 ICMP error to inside, got %d", inside.count())
	}

	inPkt := inside.last()
	// Outer dst should be the original inside client.
	outerDstIP := netip.AddrFrom4([4]byte(inPkt[16:20]))
	if outerDstIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("outer dst = %s, want 10.0.0.2", outerDstIP)
	}

	// Embedded src IP should be restored to inside client.
	embSrcIP := netip.AddrFrom4([4]byte(inPkt[40:44])) // 28(outer IP+ICMP hdr) + 12(emb IP src offset)
	if embSrcIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("embedded src = %s, want 10.0.0.2", embSrcIP)
	}

	// Embedded src port should be restored to 5000.
	embSrcPort := binary.BigEndian.Uint16(inPkt[48:50]) // 28(outer) + 20(embedded IP)
	if embSrcPort != 5000 {
		t.Errorf("embedded src port = %d, want 5000", embSrcPort)
	}
}

func TestNAT_MultipleClients(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	outside := &recorder{addr: netip.MustParsePrefix("192.168.1.1/24")}
	pktkit.ConnectL3(n.Outside(), outside)

	// Two clients send to the same destination.
	pkt1 := makeIPv4TCP(netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("8.8.8.8"), 5000, 80, 0x02)
	pkt2 := makeIPv4TCP(netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("8.8.8.8"), 5000, 80, 0x02)

	n.Inside().Send(pkt1)
	n.Inside().Send(pkt2)

	if outside.count() != 2 {
		t.Fatalf("expected 2 outbound packets, got %d", outside.count())
	}

	// They should get different mapped ports.
	port1 := binary.BigEndian.Uint16(outside.received[0][20:22])
	port2 := binary.BigEndian.Uint16(outside.received[1][20:22])
	if port1 == port2 {
		t.Errorf("two clients got same mapped port: %d", port1)
	}
}

func TestNAT_NoMapping_Drops(t *testing.T) {
	n := New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("192.168.1.100/24"),
	)
	defer n.Close()

	inside := &recorder{addr: netip.MustParsePrefix("10.0.0.2/24")}
	pktkit.ConnectL3(n.Inside(), inside)

	// Unsolicited inbound — no mapping exists, should be dropped.
	pkt := makeIPv4TCP(
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("192.168.1.100"),
		80, 12345, 0x02,
	)
	n.Outside().Send(pkt)

	if inside.count() != 0 {
		t.Errorf("unsolicited inbound should be dropped, got %d", inside.count())
	}
}
