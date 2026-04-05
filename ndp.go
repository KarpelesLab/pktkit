package pktkit

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	icmpv6NeighborSolicitation  = 135
	icmpv6NeighborAdvertisement = 136
	icmpv6RouterSolicitation    = 133
	icmpv6RouterAdvertisement   = 134

	ndpOptSourceLinkAddr = 1
	ndpOptTargetLinkAddr = 2
	ndpOptPrefixInfo     = 3

	ndpDefaultTTL = 5 * time.Minute
)

// ndpEntry is a neighbor cache entry mapping an IPv6 address to a MAC.
type ndpEntry struct {
	mac     net.HardwareAddr
	expires time.Time
}

// ndpTable is a thread-safe NDP neighbor cache.
type ndpTable struct {
	mu      sync.RWMutex
	entries map[netip.Addr]ndpEntry
}

func newNDPTable() *ndpTable {
	return &ndpTable{entries: make(map[netip.Addr]ndpEntry)}
}

func (t *ndpTable) Lookup(ip netip.Addr) (net.HardwareAddr, bool) {
	t.mu.RLock()
	e, ok := t.entries[ip]
	t.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		t.mu.Lock()
		// Re-check under write lock: another goroutine may have refreshed this entry.
		if e2, ok := t.entries[ip]; ok && time.Now().After(e2.expires) {
			delete(t.entries, ip)
		}
		t.mu.Unlock()
		return nil, false
	}
	return e.mac, true
}

func (t *ndpTable) Set(ip netip.Addr, mac net.HardwareAddr, ttl time.Duration) {
	t.mu.Lock()
	t.entries[ip] = ndpEntry{mac: mac, expires: time.Now().Add(ttl)}
	t.mu.Unlock()
}

// linkLocalFromMAC derives an IPv6 link-local address from a MAC using
// the EUI-64 method (fe80::macHigh:macFF:FEmacLow).
func linkLocalFromMAC(mac net.HardwareAddr) netip.Addr {
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	// bytes 2-7 are zero
	addr[8] = mac[0] ^ 0x02 // flip U/L bit
	addr[9] = mac[1]
	addr[10] = mac[2]
	addr[11] = 0xFF
	addr[12] = 0xFE
	addr[13] = mac[3]
	addr[14] = mac[4]
	addr[15] = mac[5]
	return netip.AddrFrom16(addr)
}

// solicitedNodeMulticast returns the solicited-node multicast address for
// the given IPv6 address (ff02::1:ffXX:XXXX using last 3 bytes).
func solicitedNodeMulticast(addr netip.Addr) netip.Addr {
	a := addr.As16()
	return netip.AddrFrom16([16]byte{
		0xff, 0x02, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0x01, 0xff, a[13], a[14], a[15],
	})
}

// solicitedNodeMAC returns the multicast MAC for a solicited-node address.
func solicitedNodeMAC(addr netip.Addr) net.HardwareAddr {
	a := addr.As16()
	return net.HardwareAddr{0x33, 0x33, 0xff, a[13], a[14], a[15]}
}

// icmpv6Checksum computes the ICMPv6 checksum over the pseudo-header and payload.
func icmpv6Checksum(src, dst netip.Addr, icmpData []byte) uint16 {
	s := src.As16()
	d := dst.As16()
	length := len(icmpData)

	// IPv6 pseudo-header
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(s[i])<<8 | uint32(s[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(d[i])<<8 | uint32(d[i+1])
	}
	sum += uint32(length)
	sum += 58 // ICMPv6 next header

	// ICMPv6 data
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(icmpData[i])<<8 | uint32(icmpData[i+1])
	}
	if length&1 != 0 {
		sum += uint32(icmpData[length-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// buildNeighborSolicitation builds an ICMPv6 Neighbor Solicitation message.
// Returns the ICMPv6 payload (to be wrapped in IPv6).
func buildNeighborSolicitation(srcMAC net.HardwareAddr, targetAddr netip.Addr) []byte {
	// NS: type(1) + code(1) + checksum(2) + reserved(4) + target(16) + option(8) = 32
	buf := make([]byte, 32)
	buf[0] = icmpv6NeighborSolicitation
	// code = 0, checksum filled later, reserved = 0
	t := targetAddr.As16()
	copy(buf[8:24], t[:])
	// Source link-layer address option (type=1, len=1 unit of 8 bytes)
	buf[24] = ndpOptSourceLinkAddr
	buf[25] = 1 // length in 8-byte units
	copy(buf[26:32], srcMAC)
	return buf
}

// buildNeighborAdvertisement builds an ICMPv6 Neighbor Advertisement message.
func buildNeighborAdvertisement(srcMAC net.HardwareAddr, targetAddr netip.Addr, solicited bool) []byte {
	buf := make([]byte, 32)
	buf[0] = icmpv6NeighborAdvertisement
	// Flags: R(0) S(solicited) O(override)
	var flags byte
	if solicited {
		flags |= 0x40 // S flag
	}
	flags |= 0x20 // O flag (override)
	buf[4] = flags
	t := targetAddr.As16()
	copy(buf[8:24], t[:])
	// Target link-layer address option
	buf[24] = ndpOptTargetLinkAddr
	buf[25] = 1
	copy(buf[26:32], srcMAC)
	return buf
}

// wrapICMPv6 wraps an ICMPv6 payload in an IPv6 packet, computing the checksum.
func wrapICMPv6(src, dst netip.Addr, icmpPayload []byte) []byte {
	// Set checksum to zero, compute, then set.
	binary.BigEndian.PutUint16(icmpPayload[2:4], 0)
	csum := icmpv6Checksum(src, dst, icmpPayload)
	binary.BigEndian.PutUint16(icmpPayload[2:4], csum)

	// IPv6 header
	ip := make([]byte, 40+len(icmpPayload))
	ip[0] = 0x60 // version 6
	binary.BigEndian.PutUint16(ip[4:6], uint16(len(icmpPayload)))
	ip[6] = 58  // next header: ICMPv6
	ip[7] = 255 // hop limit (NDP uses 255)
	s := src.As16()
	d := dst.As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	copy(ip[40:], icmpPayload)
	return ip
}

// parseNDPOption extracts the link-layer address from an NDP option list.
func parseNDPOption(opts []byte, optType byte) net.HardwareAddr {
	for len(opts) >= 8 {
		t := opts[0]
		l := int(opts[1]) * 8
		if l == 0 || l > len(opts) {
			break
		}
		if t == optType && l >= 8 {
			mac := make(net.HardwareAddr, 6)
			copy(mac, opts[2:8])
			return mac
		}
		opts = opts[l:]
	}
	return nil
}
