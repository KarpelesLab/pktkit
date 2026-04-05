package pktkit

import (
	"encoding/binary"
	"net/netip"
)

// Packet is a raw IP packet (no Ethernet header). It is a []byte type alias
// providing zero-copy typed access to IPv4 and IPv6 header fields. The
// underlying buffer is only valid during the callback that receives it.
type Packet []byte

// IsValid returns true if the packet is large enough to determine the IP version
// and contains at least the minimum header for that version.
func (p Packet) IsValid() bool {
	if len(p) < 1 {
		return false
	}
	switch p[0] >> 4 {
	case 4:
		return len(p) >= 20
	case 6:
		return len(p) >= 40
	}
	return false
}

// Version returns the IP version (4 or 6). Returns 0 if the packet is empty.
func (p Packet) Version() int {
	if len(p) < 1 {
		return 0
	}
	return int(p[0] >> 4)
}

// --- IPv4 accessors ---

// IPv4HeaderLen returns the IPv4 header length in bytes (IHL field * 4).
func (p Packet) IPv4HeaderLen() int {
	if len(p) < 1 {
		return 0
	}
	return int(p[0]&0x0F) * 4
}

// IPv4TotalLen returns the Total Length field of the IPv4 header.
func (p Packet) IPv4TotalLen() uint16 {
	if len(p) < 4 {
		return 0
	}
	return binary.BigEndian.Uint16(p[2:4])
}

// IPv4TTL returns the Time To Live field.
func (p Packet) IPv4TTL() uint8 {
	if len(p) < 9 {
		return 0
	}
	return p[8]
}

// IPv4Protocol returns the Protocol field.
func (p Packet) IPv4Protocol() Protocol {
	if len(p) < 10 {
		return 0
	}
	return Protocol(p[9])
}

// IPv4SrcAddr returns the source IPv4 address.
func (p Packet) IPv4SrcAddr() netip.Addr {
	if len(p) < 16 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(p[12:16]))
}

// IPv4DstAddr returns the destination IPv4 address.
func (p Packet) IPv4DstAddr() netip.Addr {
	if len(p) < 20 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(p[16:20]))
}

// IPv4Payload returns the IPv4 payload (data after the header).
func (p Packet) IPv4Payload() []byte {
	hl := p.IPv4HeaderLen()
	tl := int(p.IPv4TotalLen())
	if hl == 0 || tl < hl || len(p) < tl {
		return nil
	}
	return p[hl:tl]
}

// SetIPv4SrcAddr writes the source IPv4 address in place.
func (p Packet) SetIPv4SrcAddr(addr netip.Addr) {
	if len(p) < 16 {
		return
	}
	a := addr.As4()
	copy(p[12:16], a[:])
}

// SetIPv4DstAddr writes the destination IPv4 address in place.
func (p Packet) SetIPv4DstAddr(addr netip.Addr) {
	if len(p) < 20 {
		return
	}
	a := addr.As4()
	copy(p[16:20], a[:])
}

// --- IPv6 accessors ---

// IPv6PayloadLen returns the Payload Length field of the IPv6 header.
func (p Packet) IPv6PayloadLen() uint16 {
	if len(p) < 6 {
		return 0
	}
	return binary.BigEndian.Uint16(p[4:6])
}

// IPv6NextHeader returns the Next Header field (equivalent to IPv4 Protocol).
func (p Packet) IPv6NextHeader() Protocol {
	if len(p) < 7 {
		return 0
	}
	return Protocol(p[6])
}

// IPv6HopLimit returns the Hop Limit field.
func (p Packet) IPv6HopLimit() uint8 {
	if len(p) < 8 {
		return 0
	}
	return p[7]
}

// IPv6SrcAddr returns the source IPv6 address.
func (p Packet) IPv6SrcAddr() netip.Addr {
	if len(p) < 24 {
		return netip.Addr{}
	}
	return netip.AddrFrom16([16]byte(p[8:24]))
}

// IPv6DstAddr returns the destination IPv6 address.
func (p Packet) IPv6DstAddr() netip.Addr {
	if len(p) < 40 {
		return netip.Addr{}
	}
	return netip.AddrFrom16([16]byte(p[24:40]))
}

// IPv6Payload returns the IPv6 payload (data after the fixed 40-byte header).
func (p Packet) IPv6Payload() []byte {
	if len(p) < 40 {
		return nil
	}
	pl := int(p.IPv6PayloadLen())
	end := 40 + pl
	if end > len(p) {
		return nil
	}
	return p[40:end]
}

// --- Version-independent accessors ---

// SrcAddr returns the source IP address, dispatching on Version.
func (p Packet) SrcAddr() netip.Addr {
	switch p.Version() {
	case 4:
		return p.IPv4SrcAddr()
	case 6:
		return p.IPv6SrcAddr()
	}
	return netip.Addr{}
}

// DstAddr returns the destination IP address, dispatching on Version.
func (p Packet) DstAddr() netip.Addr {
	switch p.Version() {
	case 4:
		return p.IPv4DstAddr()
	case 6:
		return p.IPv6DstAddr()
	}
	return netip.Addr{}
}

// IPProtocol returns the IP protocol number, dispatching on Version.
func (p Packet) IPProtocol() Protocol {
	switch p.Version() {
	case 4:
		return p.IPv4Protocol()
	case 6:
		return p.IPv6NextHeader()
	}
	return 0
}

// Payload returns the IP payload, dispatching on Version.
func (p Packet) Payload() []byte {
	switch p.Version() {
	case 4:
		return p.IPv4Payload()
	case 6:
		return p.IPv6Payload()
	}
	return nil
}

// IsBroadcast returns true if the destination is the IPv4 limited broadcast
// address (255.255.255.255). IPv6 has no broadcast; use IsMulticast instead.
func (p Packet) IsBroadcast() bool {
	if p.Version() != 4 || len(p) < 20 {
		return false
	}
	return p[16] == 0xff && p[17] == 0xff && p[18] == 0xff && p[19] == 0xff
}

// IsMulticast returns true if the destination is a multicast address
// (IPv4 224.0.0.0/4 or IPv6 ff00::/8).
func (p Packet) IsMulticast() bool {
	switch p.Version() {
	case 4:
		if len(p) < 20 {
			return false
		}
		return p[16]&0xF0 == 0xE0
	case 6:
		if len(p) < 40 {
			return false
		}
		return p[24] == 0xFF
	}
	return false
}
