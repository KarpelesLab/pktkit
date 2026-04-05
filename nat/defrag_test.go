package nat

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// makeIPv4Fragment builds an IPv4 fragment with the given parameters.
// payload is the fragment data, mf = More Fragments flag, fragOffset is in bytes (will be divided by 8).
func makeIPv4Fragment(srcIP, dstIP netip.Addr, id uint16, proto byte, fragOffset int, mf bool, payload []byte) pktkit.Packet {
	ihl := 20
	totalLen := ihl + len(payload)
	pkt := make(pktkit.Packet, totalLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 64
	pkt[9] = proto

	flagsOff := uint16(fragOffset / 8)
	if mf {
		flagsOff |= 0x2000
	}
	binary.BigEndian.PutUint16(pkt[6:8], flagsOff)

	s := srcIP.As4()
	d := dstIP.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))

	copy(pkt[ihl:], payload)
	return pkt
}

func TestDefragNonFragment(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	// Normal unfragmented UDP packet — should pass through.
	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")
	payload := []byte("hello")
	pkt := makeIPv4UDP(src, dst, 1234, 5678, payload)

	result := d.Process(pkt)
	if result == nil {
		t.Fatal("unfragmented packet should pass through")
	}
	if len(result) != len(pkt) {
		t.Fatalf("expected len %d, got %d", len(pkt), len(result))
	}
}

func TestDefragTwoFragments(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	// Build a 400-byte payload split into two fragments.
	fullPayload := make([]byte, 400)
	for i := range fullPayload {
		fullPayload[i] = byte(i)
	}

	// Fragment 1: offset=0, MF=1, first 200 bytes
	frag1 := makeIPv4Fragment(src, dst, 0x1234, protoUDP, 0, true, fullPayload[:200])
	// Fragment 2: offset=200, MF=0, next 200 bytes
	frag2 := makeIPv4Fragment(src, dst, 0x1234, protoUDP, 200, false, fullPayload[200:])

	result := d.Process(frag1)
	if result != nil {
		t.Fatal("first fragment should return nil")
	}

	result = d.Process(frag2)
	if result == nil {
		t.Fatal("second fragment should complete reassembly")
	}

	// Verify reassembled payload
	ihl := int(result[0]&0x0F) * 4
	reassembled := result[ihl:]
	if len(reassembled) != 400 {
		t.Fatalf("expected 400 bytes payload, got %d", len(reassembled))
	}
	for i := range fullPayload {
		if reassembled[i] != fullPayload[i] {
			t.Fatalf("payload mismatch at byte %d", i)
		}
	}

	// Verify total length in IP header
	totalLen := binary.BigEndian.Uint16(result[2:4])
	if int(totalLen) != ihl+400 {
		t.Fatalf("total length = %d, want %d", totalLen, ihl+400)
	}

	// Verify MF flag cleared and offset=0
	flagsOff := binary.BigEndian.Uint16(result[6:8])
	if flagsOff != 0 {
		t.Fatalf("flags+offset = 0x%04x, want 0", flagsOff)
	}
}

func TestDefragOutOfOrder(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	payload := make([]byte, 400)
	for i := range payload {
		payload[i] = byte(i)
	}

	// Send fragment 2 first, then fragment 1.
	frag2 := makeIPv4Fragment(src, dst, 0xABCD, protoTCP, 200, false, payload[200:])
	frag1 := makeIPv4Fragment(src, dst, 0xABCD, protoTCP, 0, true, payload[:200])

	result := d.Process(frag2)
	if result != nil {
		t.Fatal("second fragment alone should not complete")
	}

	result = d.Process(frag1)
	if result == nil {
		t.Fatal("first fragment should complete reassembly")
	}

	ihl := int(result[0]&0x0F) * 4
	reassembled := result[ihl:]
	for i := range payload {
		if reassembled[i] != payload[i] {
			t.Fatalf("out-of-order reassembly mismatch at byte %d", i)
		}
	}
}

func TestDefragThreeFragments(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	payload := make([]byte, 480)
	for i := range payload {
		payload[i] = byte(i)
	}

	// 3 fragments: 0-159, 160-319, 320-479
	frag1 := makeIPv4Fragment(src, dst, 1, protoUDP, 0, true, payload[:160])
	frag2 := makeIPv4Fragment(src, dst, 1, protoUDP, 160, true, payload[160:320])
	frag3 := makeIPv4Fragment(src, dst, 1, protoUDP, 320, false, payload[320:])

	if d.Process(frag1) != nil {
		t.Fatal("frag1 should not complete")
	}
	if d.Process(frag2) != nil {
		t.Fatal("frag2 should not complete")
	}
	result := d.Process(frag3)
	if result == nil {
		t.Fatal("frag3 should complete reassembly")
	}

	ihl := int(result[0]&0x0F) * 4
	if len(result[ihl:]) != 480 {
		t.Fatalf("expected 480 bytes, got %d", len(result[ihl:]))
	}
}

func TestDefragMaxEntries(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	src := netip.MustParseAddr("10.0.0.1")
	dst := netip.MustParseAddr("10.0.0.2")

	// Fill up to defragMaxEntries (256) with different IP IDs
	for i := 0; i < defragMaxEntries; i++ {
		frag := makeIPv4Fragment(src, dst, uint16(i), protoUDP, 0, true, []byte("data"))
		d.Process(frag)
	}

	// The 257th should be dropped (returns nil)
	frag := makeIPv4Fragment(src, dst, uint16(defragMaxEntries), protoUDP, 0, true, []byte("data"))
	result := d.Process(frag)
	if result != nil {
		t.Fatal("should reject when max entries reached")
	}
}

func TestDefragShortPacket(t *testing.T) {
	d := newDefragger()
	defer d.Close()

	// Packet shorter than 20 bytes — should pass through.
	short := pktkit.Packet([]byte{0x45, 0, 0, 10})
	result := d.Process(short)
	if result == nil {
		t.Fatal("short packet should pass through")
	}
}

func TestDefragClose(t *testing.T) {
	d := newDefragger()
	d.Close()
	// Double close should not panic.
	d.Close()
}

func TestDefragEnableOnNAT(t *testing.T) {
	inAddr := netip.MustParsePrefix("10.0.0.0/24")
	outAddr := netip.MustParsePrefix("192.168.1.100/24")
	n := New(inAddr, outAddr)
	defer n.Close()

	n.EnableDefrag()
	// Enable again — should replace without panic.
	n.EnableDefrag()
}
