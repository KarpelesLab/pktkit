package pktkit

import (
	"encoding/binary"
	"net"
)

// Frame is a raw Ethernet frame. It is a []byte type alias providing zero-copy
// typed access to header fields. The underlying buffer is only valid during the
// callback that receives it; callers must copy if they need to retain the data.
type Frame []byte

// NewFrame constructs an Ethernet frame from the given header fields and payload.
func NewFrame(dst, src net.HardwareAddr, etherType EtherType, payload []byte) Frame {
	f := make(Frame, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], uint16(etherType))
	copy(f[14:], payload)
	return f
}

// IsValid returns true if the frame is large enough to contain an Ethernet header.
func (f Frame) IsValid() bool {
	return len(f) >= 14
}

// DstMAC returns the destination MAC address. Returns nil if the frame is invalid.
func (f Frame) DstMAC() net.HardwareAddr {
	if len(f) < 14 {
		return nil
	}
	return net.HardwareAddr(f[0:6])
}

// SrcMAC returns the source MAC address. Returns nil if the frame is invalid.
func (f Frame) SrcMAC() net.HardwareAddr {
	if len(f) < 14 {
		return nil
	}
	return net.HardwareAddr(f[6:12])
}

// HasVLAN returns true if the frame has an 802.1Q VLAN tag.
func (f Frame) HasVLAN() bool {
	if len(f) < 18 {
		return false
	}
	return binary.BigEndian.Uint16(f[12:14]) == uint16(EtherTypeVLAN)
}

// VLANID returns the VLAN identifier. Only valid if HasVLAN returns true.
func (f Frame) VLANID() uint16 {
	if !f.HasVLAN() {
		return 0
	}
	return binary.BigEndian.Uint16(f[14:16]) & 0x0FFF
}

// EtherType returns the protocol type of the frame payload.
// Handles 802.1Q tagged frames transparently.
func (f Frame) EtherType() EtherType {
	if len(f) < 14 {
		return 0
	}
	et := EtherType(binary.BigEndian.Uint16(f[12:14]))
	if et == EtherTypeVLAN && len(f) >= 18 {
		return EtherType(binary.BigEndian.Uint16(f[16:18]))
	}
	return et
}

// HeaderLen returns the Ethernet header length in bytes (14 normally, 18 with VLAN tag).
func (f Frame) HeaderLen() int {
	if f.HasVLAN() {
		return 18
	}
	return 14
}

// Payload returns the frame payload (everything after the Ethernet header).
func (f Frame) Payload() []byte {
	hl := f.HeaderLen()
	if len(f) < hl {
		return nil
	}
	return f[hl:]
}

// IsBroadcast returns true if the destination MAC is the broadcast address.
func (f Frame) IsBroadcast() bool {
	if len(f) < 6 {
		return false
	}
	return f[0] == 0xff && f[1] == 0xff && f[2] == 0xff && f[3] == 0xff && f[4] == 0xff && f[5] == 0xff
}

// IsMulticast returns true if the destination MAC has the multicast bit set.
func (f Frame) IsMulticast() bool {
	if len(f) < 1 {
		return false
	}
	return f[0]&1 != 0
}

// SetDstMAC writes the destination MAC address in place.
func (f Frame) SetDstMAC(mac net.HardwareAddr) {
	copy(f[0:6], mac)
}

// SetSrcMAC writes the source MAC address in place.
func (f Frame) SetSrcMAC(mac net.HardwareAddr) {
	copy(f[6:12], mac)
}
