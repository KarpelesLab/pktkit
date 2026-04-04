package slirp

import (
	"encoding/binary"
	"testing"
)

func BenchmarkBuildPacket4(b *testing.B) {
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{10, 0, 0, 2}
	// Build a realistic TCP segment (20-byte header + 1440-byte payload).
	tcpSeg := make([]byte, 1460)
	binary.BigEndian.PutUint16(tcpSeg[0:2], 12345)
	binary.BigEndian.PutUint16(tcpSeg[2:4], 80)
	binary.BigEndian.PutUint32(tcpSeg[4:8], 1000)
	binary.BigEndian.PutUint32(tcpSeg[8:12], 2000)
	tcpSeg[12] = 0x50 // data offset = 5
	tcpSeg[13] = 0x10 // ACK
	binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)

	b.ReportAllocs()
	b.SetBytes(int64(20 + len(tcpSeg))) // IP header + TCP segment
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildPacket4(srcIP, dstIP, tcpSeg)
	}
}

func BenchmarkBuildPacket6(b *testing.B) {
	srcIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	tcpSeg := make([]byte, 1440)
	binary.BigEndian.PutUint16(tcpSeg[0:2], 12345)
	binary.BigEndian.PutUint16(tcpSeg[2:4], 443)
	binary.BigEndian.PutUint32(tcpSeg[4:8], 1000)
	binary.BigEndian.PutUint32(tcpSeg[8:12], 2000)
	tcpSeg[12] = 0x50
	tcpSeg[13] = 0x10
	binary.BigEndian.PutUint16(tcpSeg[14:16], 65535)

	b.ReportAllocs()
	b.SetBytes(int64(40 + len(tcpSeg)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildPacket6(srcIP, dstIP, tcpSeg)
	}
}

func BenchmarkIPChecksum(b *testing.B) {
	hdr := make([]byte, 20)
	hdr[0] = 0x45
	binary.BigEndian.PutUint16(hdr[2:4], 1500)
	hdr[8] = 64
	hdr[9] = 6
	copy(hdr[12:16], []byte{10, 0, 0, 1})
	copy(hdr[16:20], []byte{10, 0, 0, 2})

	b.ReportAllocs()
	b.SetBytes(20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IPChecksum(hdr)
	}
}

func BenchmarkTCPChecksum(b *testing.B) {
	srcIP := []byte{10, 0, 0, 1}
	dstIP := []byte{10, 0, 0, 2}
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 12345)
	binary.BigEndian.PutUint16(hdr[2:4], 80)
	hdr[12] = 0x50
	hdr[13] = 0x10
	binary.BigEndian.PutUint16(hdr[14:16], 65535)
	payload := make([]byte, 1440)

	b.ReportAllocs()
	b.SetBytes(int64(len(hdr) + len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TCPChecksum(srcIP, dstIP, hdr, payload)
	}
}

func BenchmarkIPv6Checksum(b *testing.B) {
	srcIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	dstIP := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	data := make([]byte, 1460)
	// Fill with pattern to exercise the checksum path.
	for i := range data {
		data[i] = byte(i)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IPv6Checksum(srcIP, dstIP, 6, uint32(len(data)), data)
	}
}
