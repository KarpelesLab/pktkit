package pktkit

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// helper: build a minimal valid Ethernet frame (14 bytes header + payload).
func makeFrame(dst, src net.HardwareAddr, et EtherType, payload []byte) Frame {
	f := make(Frame, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], uint16(et))
	copy(f[14:], payload)
	return f
}

// helper: build a VLAN-tagged Ethernet frame (18 bytes header + payload).
func makeVLANFrame(dst, src net.HardwareAddr, vlanID uint16, innerET EtherType, payload []byte) Frame {
	f := make(Frame, 18+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], uint16(EtherTypeVLAN))
	binary.BigEndian.PutUint16(f[14:16], vlanID&0x0FFF)
	binary.BigEndian.PutUint16(f[16:18], uint16(innerET))
	copy(f[18:], payload)
	return f
}

var (
	macA     = net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01}
	macB     = net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	macBcast = net.HardwareAddr{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	macMcast = net.HardwareAddr{0x01, 0x00, 0x5E, 0x00, 0x00, 0x01} // bit 0 set
)

// ---------- NewFrame ----------

func TestNewFrame(t *testing.T) {
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	f := NewFrame(macA, macB, EtherTypeIPv4, payload)

	if len(f) != 14+len(payload) {
		t.Fatalf("NewFrame length = %d, want %d", len(f), 14+len(payload))
	}
	if got := net.HardwareAddr(f[0:6]); !bytes.Equal(got, macA) {
		t.Errorf("dst MAC = %s, want %s", got, macA)
	}
	if got := net.HardwareAddr(f[6:12]); !bytes.Equal(got, macB) {
		t.Errorf("src MAC = %s, want %s", got, macB)
	}
	if got := binary.BigEndian.Uint16(f[12:14]); got != uint16(EtherTypeIPv4) {
		t.Errorf("ethertype = 0x%04x, want 0x%04x", got, uint16(EtherTypeIPv4))
	}
	if !bytes.Equal(f[14:], payload) {
		t.Errorf("payload = %x, want %x", f[14:], payload)
	}
}

func TestNewFrameEmptyPayload(t *testing.T) {
	f := NewFrame(macA, macB, EtherTypeIPv6, nil)
	if len(f) != 14 {
		t.Fatalf("NewFrame with nil payload: length = %d, want 14", len(f))
	}
}

// ---------- IsValid ----------

func TestIsValid(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
		want  bool
	}{
		{"exactly 14 bytes", make(Frame, 14), true},
		{"larger frame", make(Frame, 60), true},
		{"13 bytes (too short)", make(Frame, 13), false},
		{"empty", Frame{}, false},
		{"nil", Frame(nil), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.frame.IsValid(); got != tc.want {
				t.Errorf("IsValid() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------- DstMAC / SrcMAC ----------

func TestDstMAC(t *testing.T) {
	f := makeFrame(macA, macB, EtherTypeIPv4, nil)
	got := f.DstMAC()
	if !bytes.Equal(got, macA) {
		t.Errorf("DstMAC() = %s, want %s", got, macA)
	}
}

func TestSrcMAC(t *testing.T) {
	f := makeFrame(macA, macB, EtherTypeIPv4, nil)
	got := f.SrcMAC()
	if !bytes.Equal(got, macB) {
		t.Errorf("SrcMAC() = %s, want %s", got, macB)
	}
}

func TestDstMACInvalid(t *testing.T) {
	f := Frame(make([]byte, 5))
	if got := f.DstMAC(); got != nil {
		t.Errorf("DstMAC() on short frame = %s, want nil", got)
	}
}

func TestSrcMACInvalid(t *testing.T) {
	f := Frame(make([]byte, 5))
	if got := f.SrcMAC(); got != nil {
		t.Errorf("SrcMAC() on short frame = %s, want nil", got)
	}
}

// ---------- EtherType ----------

func TestEtherType(t *testing.T) {
	tests := []struct {
		name string
		f    Frame
		want EtherType
	}{
		{
			"IPv4",
			makeFrame(macA, macB, EtherTypeIPv4, []byte{0x00}),
			EtherTypeIPv4,
		},
		{
			"IPv6",
			makeFrame(macA, macB, EtherTypeIPv6, []byte{0x00}),
			EtherTypeIPv6,
		},
		{
			"VLAN tagged (inner IPv4)",
			makeVLANFrame(macA, macB, 100, EtherTypeIPv4, []byte{0x00}),
			EtherTypeIPv4,
		},
		{
			"short frame",
			Frame(make([]byte, 10)),
			EtherType(0),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.f.EtherType(); got != tc.want {
				t.Errorf("EtherType() = 0x%04x, want 0x%04x", got, tc.want)
			}
		})
	}
}

// ---------- HasVLAN / VLANID ----------

func TestHasVLAN(t *testing.T) {
	plain := makeFrame(macA, macB, EtherTypeIPv4, []byte("data"))
	if plain.HasVLAN() {
		t.Error("HasVLAN() = true for non-VLAN frame")
	}

	vlan := makeVLANFrame(macA, macB, 42, EtherTypeIPv4, []byte("data"))
	if !vlan.HasVLAN() {
		t.Error("HasVLAN() = false for VLAN frame")
	}
}

func TestVLANID(t *testing.T) {
	tests := []struct {
		name string
		id   uint16
	}{
		{"VLAN 1", 1},
		{"VLAN 100", 100},
		{"VLAN 4095 (max)", 4095},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := makeVLANFrame(macA, macB, tc.id, EtherTypeIPv4, nil)
			if got := f.VLANID(); got != tc.id {
				t.Errorf("VLANID() = %d, want %d", got, tc.id)
			}
		})
	}
}

func TestVLANIDNoTag(t *testing.T) {
	f := makeFrame(macA, macB, EtherTypeIPv4, []byte("data"))
	if got := f.VLANID(); got != 0 {
		t.Errorf("VLANID() on non-VLAN frame = %d, want 0", got)
	}
}

// ---------- HeaderLen ----------

func TestHeaderLen(t *testing.T) {
	plain := makeFrame(macA, macB, EtherTypeIPv4, []byte{0x00})
	if got := plain.HeaderLen(); got != 14 {
		t.Errorf("HeaderLen() = %d, want 14", got)
	}

	vlan := makeVLANFrame(macA, macB, 10, EtherTypeIPv4, []byte{0x00})
	if got := vlan.HeaderLen(); got != 18 {
		t.Errorf("HeaderLen() VLAN = %d, want 18", got)
	}
}

// ---------- Payload ----------

func TestPayload(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	plain := makeFrame(macA, macB, EtherTypeIPv4, data)
	got := plain.Payload()
	if !bytes.Equal(got, data) {
		t.Errorf("Payload() = %x, want %x", got, data)
	}

	vlan := makeVLANFrame(macA, macB, 10, EtherTypeIPv4, data)
	got = vlan.Payload()
	if !bytes.Equal(got, data) {
		t.Errorf("Payload() VLAN = %x, want %x", got, data)
	}
}

func TestPayloadTooShort(t *testing.T) {
	// Frame shorter than header: Payload returns nil.
	f := Frame(make([]byte, 10))
	if got := f.Payload(); got != nil {
		t.Errorf("Payload() on short frame = %x, want nil", got)
	}
}

// ---------- IsBroadcast ----------

func TestIsBroadcast(t *testing.T) {
	bcast := makeFrame(macBcast, macB, EtherTypeIPv4, nil)
	if !bcast.IsBroadcast() {
		t.Error("IsBroadcast() = false for broadcast dst")
	}

	unicast := makeFrame(macA, macB, EtherTypeIPv4, nil)
	if unicast.IsBroadcast() {
		t.Error("IsBroadcast() = true for unicast dst")
	}

	short := Frame(make([]byte, 3))
	if short.IsBroadcast() {
		t.Error("IsBroadcast() = true for short frame")
	}
}

// ---------- IsMulticast ----------

func TestIsMulticast(t *testing.T) {
	mcast := makeFrame(macMcast, macB, EtherTypeIPv4, nil)
	if !mcast.IsMulticast() {
		t.Error("IsMulticast() = false for multicast dst")
	}

	// Broadcast is also multicast (bit 0 of 0xFF is set).
	bcast := makeFrame(macBcast, macB, EtherTypeIPv4, nil)
	if !bcast.IsMulticast() {
		t.Error("IsMulticast() = false for broadcast dst (should be true)")
	}

	unicast := makeFrame(macA, macB, EtherTypeIPv4, nil)
	if unicast.IsMulticast() {
		t.Error("IsMulticast() = true for unicast dst")
	}

	empty := Frame{}
	if empty.IsMulticast() {
		t.Error("IsMulticast() = true for empty frame")
	}
}

// ---------- SetDstMAC / SetSrcMAC ----------

func TestSetDstMAC(t *testing.T) {
	f := makeFrame(macA, macB, EtherTypeIPv4, []byte{0x00})
	newDst := net.HardwareAddr{0xDE, 0xAD, 0x00, 0x00, 0x00, 0x01}
	f.SetDstMAC(newDst)
	if got := f.DstMAC(); !bytes.Equal(got, newDst) {
		t.Errorf("after SetDstMAC, DstMAC() = %s, want %s", got, newDst)
	}
	// SrcMAC must be unchanged.
	if got := f.SrcMAC(); !bytes.Equal(got, macB) {
		t.Errorf("SetDstMAC mutated SrcMAC: got %s, want %s", got, macB)
	}
}

func TestSetSrcMAC(t *testing.T) {
	f := makeFrame(macA, macB, EtherTypeIPv4, []byte{0x00})
	newSrc := net.HardwareAddr{0xBE, 0xEF, 0x00, 0x00, 0x00, 0x02}
	f.SetSrcMAC(newSrc)
	if got := f.SrcMAC(); !bytes.Equal(got, newSrc) {
		t.Errorf("after SetSrcMAC, SrcMAC() = %s, want %s", got, newSrc)
	}
	// DstMAC must be unchanged.
	if got := f.DstMAC(); !bytes.Equal(got, macA) {
		t.Errorf("SetSrcMAC mutated DstMAC: got %s, want %s", got, macA)
	}
}
