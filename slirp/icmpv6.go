package slirp

import (
	"encoding/binary"
)

// ICMPv6 Type codes
const (
	ICMPv6TypeEchoRequest           = 128
	ICMPv6TypeEchoReply             = 129
	ICMPv6TypeRouterSolicitation    = 133
	ICMPv6TypeRouterAdvertisement   = 134
	ICMPv6TypeNeighborSolicitation  = 135
	ICMPv6TypeNeighborAdvertisement = 136
)

// handleICMPv6 processes ICMPv6 packets (legacy ns=0 path).
func (s *Stack) handleICMPv6(packet []byte, srcIP, dstIP [16]byte, transportOff int) error {
	return s.handleICMPv6ns(0, packet, srcIP, dstIP, transportOff)
}

// handleICMPv6ns processes ICMPv6 packets with namespace routing.
func (s *Stack) handleICMPv6ns(ns uint64, packet []byte, srcIP, dstIP [16]byte, transportOff int) error {
	if len(packet) < transportOff+8 {
		return nil
	}

	icmp := packet[transportOff:]
	if len(icmp) < 8 {
		return nil
	}

	icmpType := icmp[0]

	switch icmpType {
	case ICMPv6TypeEchoRequest:
		return s.handleICMPv6EchoRequestNs(ns, packet, srcIP, dstIP, transportOff)

	case ICMPv6TypeRouterSolicitation:
		// Router Solicitation - typically we ignore this in a NAT context
		return nil

	case ICMPv6TypeNeighborSolicitation, ICMPv6TypeNeighborAdvertisement, ICMPv6TypeRouterAdvertisement:
		// L2 concerns — ignored in pure L3 mode
		return nil

	default:
		return nil
	}
}

// handleICMPv6EchoRequestNs handles ping6 requests with namespace routing.
func (s *Stack) handleICMPv6EchoRequestNs(ns uint64, packet []byte, srcIP, dstIP [16]byte, transportOff int) error {
	if len(packet) < transportOff+8 {
		return nil
	}
	icmp := packet[transportOff:]
	if len(icmp) < 8 {
		return nil
	}

	// Build Echo Reply
	replyICMP := make([]byte, len(icmp))
	copy(replyICMP, icmp)
	replyICMP[0] = ICMPv6TypeEchoReply // Change type to Echo Reply
	replyICMP[1] = 0                   // Code = 0

	// Recalculate checksum
	binary.BigEndian.PutUint16(replyICMP[2:4], 0)
	checksum := IPv6Checksum(dstIP, srcIP, 58, uint32(len(replyICMP)), replyICMP)
	binary.BigEndian.PutUint16(replyICMP[2:4], checksum)

	// Build IPv6 header
	ip := make([]byte, 40)
	ip[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(replyICMP)))
	ip[6] = 58                // Next Header: ICMPv6
	ip[7] = 64                // Hop Limit
	copy(ip[8:24], dstIP[:])  // Source = original dest
	copy(ip[24:40], srcIP[:]) // Dest = original source

	// Build raw IP packet (no Ethernet header)
	pkt := make([]byte, len(ip)+len(replyICMP))
	copy(pkt, ip)
	copy(pkt[len(ip):], replyICMP)

	return s.sendTo(ns, pkt)
}
