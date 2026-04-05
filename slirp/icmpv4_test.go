package slirp

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

func TestICMPv4EchoRequest(t *testing.T) {
	s := New()
	defer s.Close()
	s.SetAddr(netip.MustParsePrefix("10.0.0.1/24"))

	var reply []byte
	h := func(p pktkit.Packet) error {
		reply = make([]byte, len(p))
		copy(reply, p)
		return nil
	}
	s.SetHandler(h)

	// Build an ICMP echo request to 10.0.0.1 from 10.0.0.2.
	srcIP := [4]byte{10, 0, 0, 2}
	dstIP := [4]byte{10, 0, 0, 1}

	pkt := make([]byte, 28)                  // 20 IP + 8 ICMP
	pkt[0] = 0x45                            // IPv4, IHL=5
	binary.BigEndian.PutUint16(pkt[2:4], 28) // total length
	pkt[8] = 64                              // TTL
	pkt[9] = 1                               // protocol: ICMP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])

	// IP checksum.
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))

	// ICMP echo request.
	icmp := pkt[20:]
	icmp[0] = 8                                   // type: echo request
	icmp[1] = 0                                   // code
	binary.BigEndian.PutUint16(icmp[4:6], 0x1234) // identifier
	binary.BigEndian.PutUint16(icmp[6:8], 1)      // sequence
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(icmp))

	if err := s.Send(pkt); err != nil {
		t.Fatal(err)
	}

	if reply == nil {
		t.Fatal("no reply received")
	}
	if len(reply) != 28 {
		t.Fatalf("reply length = %d, want 28", len(reply))
	}

	// Check reply is ICMP echo reply.
	if reply[9] != 1 {
		t.Errorf("protocol = %d, want 1 (ICMP)", reply[9])
	}
	replyICMP := reply[20:]
	if replyICMP[0] != 0 {
		t.Errorf("ICMP type = %d, want 0 (echo reply)", replyICMP[0])
	}
	// Identifier should be preserved.
	if binary.BigEndian.Uint16(replyICMP[4:6]) != 0x1234 {
		t.Errorf("identifier = 0x%04x, want 0x1234", binary.BigEndian.Uint16(replyICMP[4:6]))
	}
	// Src/dst should be swapped.
	if reply[12] != 10 || reply[13] != 0 || reply[14] != 0 || reply[15] != 1 {
		t.Errorf("reply src = %d.%d.%d.%d, want 10.0.0.1", reply[12], reply[13], reply[14], reply[15])
	}
	if reply[16] != 10 || reply[17] != 0 || reply[18] != 0 || reply[19] != 2 {
		t.Errorf("reply dst = %d.%d.%d.%d, want 10.0.0.2", reply[16], reply[17], reply[18], reply[19])
	}
}

func TestICMPv4NotOurIP(t *testing.T) {
	s := New()
	defer s.Close()
	s.SetAddr(netip.MustParsePrefix("10.0.0.1/24"))

	var replied bool
	h := func(_ pktkit.Packet) error {
		replied = true
		return nil
	}
	s.SetHandler(h)

	// Send echo request to 10.0.0.99 (not our IP) — should be dropped.
	srcIP := [4]byte{10, 0, 0, 2}
	dstIP := [4]byte{10, 0, 0, 99}

	pkt := make([]byte, 28)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 28)
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(icmp))

	s.Send(pkt)

	if replied {
		t.Error("should not reply to ICMP for non-local IP")
	}
}

func TestICMPv4WithPayload(t *testing.T) {
	s := New()
	defer s.Close()
	s.SetAddr(netip.MustParsePrefix("10.0.0.1/24"))

	var reply []byte
	h := func(p pktkit.Packet) error {
		reply = make([]byte, len(p))
		copy(reply, p)
		return nil
	}
	s.SetHandler(h)

	srcIP := [4]byte{10, 0, 0, 2}
	dstIP := [4]byte{10, 0, 0, 1}
	payload := []byte("ping-test-data")

	pktLen := 20 + 8 + len(payload)
	pkt := make([]byte, pktLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(pktLen))
	pkt[8] = 64
	pkt[9] = 1
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dstIP[:])
	binary.BigEndian.PutUint16(pkt[10:12], ipv4HeaderChecksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 42)
	binary.BigEndian.PutUint16(icmp[6:8], 7)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], icmpChecksum(icmp))

	s.Send(pkt)

	if reply == nil {
		t.Fatal("no reply")
	}
	if len(reply) != pktLen {
		t.Fatalf("reply length = %d, want %d", len(reply), pktLen)
	}

	replyICMP := reply[20:]
	if replyICMP[0] != 0 {
		t.Errorf("type = %d, want 0", replyICMP[0])
	}
	// Payload should be preserved.
	replyPayload := replyICMP[8:]
	if string(replyPayload) != "ping-test-data" {
		t.Errorf("payload = %q, want %q", replyPayload, "ping-test-data")
	}
}
