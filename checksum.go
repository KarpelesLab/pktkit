package pktkit

import (
	"net/netip"
)

// Checksum computes the Internet checksum (RFC 1071) over data.
func Checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if n&1 != 0 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// CombineChecksums folds two partial checksums into one.
func CombineChecksums(a, b uint16) uint16 {
	sum := uint32(a) + uint32(b)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// PseudoHeaderChecksum returns the checksum contribution of the TCP/UDP
// pseudo-header for the given protocol, addresses, and upper-layer length.
func PseudoHeaderChecksum(proto Protocol, src, dst netip.Addr, length uint16) uint16 {
	if src.Is4() {
		var buf [12]byte
		s := src.As4()
		d := dst.As4()
		copy(buf[0:4], s[:])
		copy(buf[4:8], d[:])
		buf[8] = 0
		buf[9] = byte(proto)
		buf[10] = byte(length >> 8)
		buf[11] = byte(length)
		return ^Checksum(buf[:]) // return raw sum (un-complemented) for combining
	}
	// IPv6 pseudo-header (RFC 2460 Section 8.1)
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
	return ^Checksum(buf[:])
}
