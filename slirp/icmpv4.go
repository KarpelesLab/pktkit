package slirp

import "encoding/binary"

// handleICMPv4 processes IPv4 ICMP packets. Only echo requests destined
// for the stack's own IP are answered; everything else is silently dropped
// (forwarding ICMP to the real network requires raw sockets / root).
func (s *Stack) handleICMPv4(ip []byte, srcIP, dstIP [4]byte, ihl int) error {
	icmp := ip[ihl:]
	if len(icmp) < 8 {
		return nil
	}

	// Only handle echo requests (type 8, code 0).
	if icmp[0] != 8 || icmp[1] != 0 {
		return nil
	}

	// Only respond if the destination is our own address.
	addr := s.Addr()
	if !addr.IsValid() {
		return nil
	}
	ourIP := addr.Addr().As4()
	if dstIP != ourIP {
		return nil
	}

	// Build echo reply: swap src/dst, change type to 0, recompute checksum.
	reply := make([]byte, len(ip))
	copy(reply, ip)

	// Swap IP src/dst.
	copy(reply[12:16], dstIP[:])
	copy(reply[16:20], srcIP[:])

	// Set TTL to 64.
	reply[8] = 64

	// ICMP: type 0 (echo reply), code 0.
	replyICMP := reply[ihl:]
	replyICMP[0] = 0
	replyICMP[1] = 0

	// Recompute ICMP checksum.
	binary.BigEndian.PutUint16(replyICMP[2:4], 0)
	binary.BigEndian.PutUint16(replyICMP[2:4], icmpChecksum(replyICMP))

	// Recompute IP header checksum.
	binary.BigEndian.PutUint16(reply[10:12], 0)
	binary.BigEndian.PutUint16(reply[10:12], ipv4HeaderChecksum(reply[:ihl]))

	return s.send(reply)
}

// icmpChecksum computes the Internet checksum over the given data.
func icmpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// ipv4HeaderChecksum computes the IPv4 header checksum.
func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

