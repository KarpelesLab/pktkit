package pktkit

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestChecksum_ValidIPv4Header(t *testing.T) {
	// A valid IPv4 header with a correct checksum should produce 0 when
	// the checksum is computed over the entire header (including the
	// checksum field itself).
	//
	// Header: Version=4, IHL=5, TotalLen=40, TTL=64, Proto=TCP(6)
	// Src=192.168.1.1, Dst=10.0.0.1
	hdr := make([]byte, 20)
	hdr[0] = 0x45             // Version=4, IHL=5
	hdr[1] = 0x00             // DSCP/ECN
	binary.BigEndian.PutUint16(hdr[2:4], 40)   // Total Length
	binary.BigEndian.PutUint16(hdr[4:6], 0x1234) // Identification
	binary.BigEndian.PutUint16(hdr[6:8], 0x0000) // Flags+FragOffset
	hdr[8] = 64               // TTL
	hdr[9] = 6                // Protocol = TCP
	// Leave checksum at [10:12] as zero for now
	copy(hdr[12:16], []byte{192, 168, 1, 1}) // Src
	copy(hdr[16:20], []byte{10, 0, 0, 1})    // Dst

	// Compute checksum with the field zeroed and fill it in.
	csum := Checksum(hdr)
	binary.BigEndian.PutUint16(hdr[10:12], csum)

	// Now checksumming the full header (including the correct checksum
	// field) must yield 0.
	if got := Checksum(hdr); got != 0 {
		t.Fatalf("Checksum over valid IPv4 header = 0x%04x; want 0x0000", got)
	}
}

func TestChecksum_SimpleData(t *testing.T) {
	// Hand-calculated: data = {0x00, 0x01, 0x00, 0x02}
	// sum = 0x0001 + 0x0002 = 0x0003
	// checksum = ^0x0003 = 0xFFFC
	data := []byte{0x00, 0x01, 0x00, 0x02}
	got := Checksum(data)
	if got != 0xFFFC {
		t.Fatalf("Checksum({00 01 00 02}) = 0x%04X; want 0xFFFC", got)
	}
}

func TestChecksum_AllZeros(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00}
	got := Checksum(data)
	if got != 0xFFFF {
		t.Fatalf("Checksum(all zeros) = 0x%04X; want 0xFFFF", got)
	}
}

func TestChecksum_AllOnes(t *testing.T) {
	data := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	// sum = 0xFFFF + 0xFFFF = 0x1FFFE → fold → 0xFFFF → complement → 0x0000
	got := Checksum(data)
	if got != 0x0000 {
		t.Fatalf("Checksum(all 0xFF) = 0x%04X; want 0x0000", got)
	}
}

func TestChecksum_OddLength(t *testing.T) {
	// Odd-length data: {0x01, 0x02, 0x03}
	// Treated as {0x01, 0x02, 0x03, 0x00} for checksum purposes.
	// sum = 0x0102 + 0x0300 = 0x0402
	// checksum = ^0x0402 = 0xFBFD
	data := []byte{0x01, 0x02, 0x03}
	got := Checksum(data)
	if got != 0xFBFD {
		t.Fatalf("Checksum({01 02 03}) = 0x%04X; want 0xFBFD", got)
	}
}

func TestChecksum_SingleByte(t *testing.T) {
	// Single byte 0xAB → padded to {0xAB, 0x00}
	// sum = 0xAB00, complement = 0x54FF
	data := []byte{0xAB}
	got := Checksum(data)
	if got != 0x54FF {
		t.Fatalf("Checksum({AB}) = 0x%04X; want 0x54FF", got)
	}
}

func TestChecksum_Empty(t *testing.T) {
	got := Checksum(nil)
	if got != 0xFFFF {
		t.Fatalf("Checksum(nil) = 0x%04X; want 0xFFFF", got)
	}
}

func TestPseudoHeaderChecksum_IPv4(t *testing.T) {
	src := netip.MustParseAddr("192.168.1.1")
	dst := netip.MustParseAddr("10.0.0.1")
	proto := ProtocolTCP
	length := uint16(20)

	got := PseudoHeaderChecksum(proto, src, dst, length)

	// Build the 12-byte pseudo-header manually and compute reference checksum.
	var buf [12]byte
	s := src.As4()
	d := dst.As4()
	copy(buf[0:4], s[:])
	copy(buf[4:8], d[:])
	buf[8] = 0
	buf[9] = byte(proto)
	buf[10] = byte(length >> 8)
	buf[11] = byte(length)
	// PseudoHeaderChecksum returns the un-complemented partial sum, which
	// is ^Checksum(buf). Compute that here.
	want := ^Checksum(buf[:])

	if got != want {
		t.Fatalf("PseudoHeaderChecksum(TCP, %s, %s, %d) = 0x%04X; want 0x%04X",
			src, dst, length, got, want)
	}
}

func TestPseudoHeaderChecksum_IPv6(t *testing.T) {
	src := netip.MustParseAddr("fe80::1")
	dst := netip.MustParseAddr("fe80::2")
	proto := ProtocolUDP
	length := uint16(100)

	got := PseudoHeaderChecksum(proto, src, dst, length)

	// Build the 40-byte IPv6 pseudo-header manually and compute reference.
	var buf [40]byte
	s := src.As16()
	d := dst.As16()
	copy(buf[0:16], s[:])
	copy(buf[16:32], d[:])
	buf[34] = byte(length >> 8)
	buf[35] = byte(length)
	buf[36] = 0
	buf[37] = 0
	buf[38] = 0
	buf[39] = byte(proto)
	want := ^Checksum(buf[:])

	if got != want {
		t.Fatalf("PseudoHeaderChecksum(UDP, %s, %s, %d) = 0x%04X; want 0x%04X",
			src, dst, length, got, want)
	}
}

func TestPseudoHeaderChecksum_IPv4_matches_raw(t *testing.T) {
	// Verify the pseudo-header checksum for a specific case with known
	// byte layout so we are not just testing against itself.
	src := netip.MustParseAddr("127.0.0.1")
	dst := netip.MustParseAddr("127.0.0.1")
	proto := ProtocolUDP
	length := uint16(8)

	got := PseudoHeaderChecksum(proto, src, dst, length)

	// Pseudo-header bytes:
	// 7f 00 00 01  7f 00 00 01  00 11 00 08
	raw := []byte{
		0x7f, 0x00, 0x00, 0x01,
		0x7f, 0x00, 0x00, 0x01,
		0x00, 0x11, 0x00, 0x08,
	}
	want := ^Checksum(raw)
	if got != want {
		t.Fatalf("PseudoHeaderChecksum(UDP, loopback, 8) = 0x%04X; want 0x%04X", got, want)
	}
}

func TestCombineChecksums(t *testing.T) {
	// Splitting data into two halves and combining partial checksums must
	// produce the same result as checksumming the whole data at once.
	data := []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04}
	whole := Checksum(data)

	// Compute partial (un-complemented) sums, then combine and complement.
	partA := ^Checksum(data[:4])
	partB := ^Checksum(data[4:])
	combined := ^CombineChecksums(partA, partB)

	if combined != whole {
		t.Fatalf("CombineChecksums(partA, partB) complement = 0x%04X; want 0x%04X",
			combined, whole)
	}
}

func TestCombineChecksums_Identity(t *testing.T) {
	// Combining with 0 should leave the value unchanged.
	val := uint16(0x1234)
	got := CombineChecksums(val, 0)
	if got != val {
		t.Fatalf("CombineChecksums(0x%04X, 0) = 0x%04X; want 0x%04X", val, got, val)
	}
}

func TestCombineChecksums_CarryFold(t *testing.T) {
	// 0xFFFF + 0x0001 = 0x10000 → after folding = 0x0001
	got := CombineChecksums(0xFFFF, 0x0001)
	if got != 0x0001 {
		t.Fatalf("CombineChecksums(0xFFFF, 0x0001) = 0x%04X; want 0x0001", got)
	}
}

func TestChecksum_RFC1071_Example(t *testing.T) {
	// RFC 1071 example: the 16-bit words 0x0001, 0xf203, 0xf4f5, 0xf6f7
	// Sum = 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2ddf0
	// Fold carry: 0xddf0 + 0x0002 = 0xddf2 (one's complement partial sum)
	// But this isn't the folded data from RFC, so let's just test the data.
	data := []byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
	got := Checksum(data)
	// sum = 0x0001 + 0xf203 + 0xf4f5 + 0xf6f7 = 0x2ddf0
	// fold: 0xddf0 + 0x2 = 0xddf2
	// complement: 0x220d
	want := uint16(0x220D)
	if got != want {
		t.Fatalf("Checksum(RFC1071 data) = 0x%04X; want 0x%04X", got, want)
	}
}

func TestChecksum_Complementary(t *testing.T) {
	// Appending the checksum to data and re-computing should yield 0.
	data := []byte{0x45, 0x00, 0x00, 0x28, 0xab, 0xcd}
	csum := Checksum(data)

	full := make([]byte, len(data)+2)
	copy(full, data)
	binary.BigEndian.PutUint16(full[len(data):], csum)
	if got := Checksum(full); got != 0 {
		t.Fatalf("Checksum after appending its own checksum = 0x%04X; want 0x0000", got)
	}
}

func TestChecksum_LargerPayload(t *testing.T) {
	// Test with a non-trivial payload to catch off-by-one errors.
	// Use incrementing bytes 0..255.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	csum := Checksum(data)
	// Verify by appending the checksum and re-checking.
	full := make([]byte, 258)
	copy(full, data)
	binary.BigEndian.PutUint16(full[256:], csum)
	if got := Checksum(full); got != 0 {
		t.Fatalf("Checksum(256-byte data + checksum) = 0x%04X; want 0x0000", got)
	}
}

func TestChecksum_OddLargePayload(t *testing.T) {
	// 255 bytes (odd length).
	data := make([]byte, 255)
	for i := range data {
		data[i] = byte(i)
	}
	csum := Checksum(data)
	// Prepend a zero byte so that appending checksum keeps even alignment.
	// Actually, just verify the checksum is non-zero and deterministic.
	csum2 := Checksum(data)
	if csum != csum2 {
		t.Fatalf("Checksum not deterministic: 0x%04X vs 0x%04X", csum, csum2)
	}
	// Also verify by padding to even then checking.
	padded := make([]byte, 256)
	copy(padded, data)
	padded[255] = 0 // explicit zero-pad
	csumPadded := Checksum(padded)
	if csum != csumPadded {
		t.Fatalf("Odd-length checksum 0x%04X differs from zero-padded even 0x%04X", csum, csumPadded)
	}
}

func TestPseudoHeaderChecksum_DifferentProtocols(t *testing.T) {
	src := netip.MustParseAddr("10.1.2.3")
	dst := netip.MustParseAddr("10.4.5.6")
	length := uint16(50)

	tcp := PseudoHeaderChecksum(ProtocolTCP, src, dst, length)
	udp := PseudoHeaderChecksum(ProtocolUDP, src, dst, length)

	if tcp == udp {
		t.Fatal("PseudoHeaderChecksum should differ between TCP and UDP")
	}

	// Verify they only differ by the protocol byte difference.
	// The partial sums should differ by (17 - 6) = 11 (UDP proto - TCP proto).
	diff := int(udp) - int(tcp)
	if diff != int(ProtocolUDP)-int(ProtocolTCP) {
		t.Fatalf("Checksum difference = %d; want %d", diff,
			int(ProtocolUDP)-int(ProtocolTCP))
	}
}

func TestPseudoHeaderChecksum_IPv6_ZeroLength(t *testing.T) {
	src := netip.MustParseAddr("::1")
	dst := netip.MustParseAddr("::2")

	got := PseudoHeaderChecksum(ProtocolTCP, src, dst, 0)

	var buf [40]byte
	s := src.As16()
	d := dst.As16()
	copy(buf[0:16], s[:])
	copy(buf[16:32], d[:])
	// length = 0 at buf[34:36], already zero
	buf[39] = byte(ProtocolTCP)
	want := ^Checksum(buf[:])

	if got != want {
		t.Fatalf("PseudoHeaderChecksum(TCP, ::1, ::2, 0) = 0x%04X; want 0x%04X", got, want)
	}
}

func BenchmarkChecksum(b *testing.B) {
	data := bytes.Repeat([]byte{0xAB, 0xCD}, 750) // 1500 bytes
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Checksum(data)
	}
}
