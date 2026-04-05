package ovpn

import (
	"bytes"
	"testing"
)

// mockPeer creates a minimal Peer for control packet testing.
func mockPeer() *Peer {
	p := &Peer{
		ctrlIn:  make(map[uint32]*ControlPacket),
		ctrlOut: make(map[uint32]*ControlPacket),
	}
	// Set session IDs
	for i := range p.localId {
		p.localId[i] = byte(i + 1)
	}
	for i := range p.peerId {
		p.peerId[i] = byte(i + 0x10)
	}
	return p
}

func TestMakeControlPacket(t *testing.T) {
	p := mockPeer()
	pkt := MakeControlPacket(p, P_CONTROL_V1, 0)
	if pkt.t != P_CONTROL_V1 {
		t.Fatalf("expected P_CONTROL_V1, got %v", pkt.t)
	}
	if pkt.kid != 0 {
		t.Fatalf("expected kid 0, got %d", pkt.kid)
	}
	if pkt.sid != p.localId {
		t.Fatal("session ID mismatch")
	}
	if pkt.RemoteId != p.peerId {
		t.Fatal("remote ID mismatch")
	}
	if pkt.hasPid {
		t.Fatal("new control packet should not have PID set")
	}
}

func TestControlPacketSetPid(t *testing.T) {
	p := mockPeer()
	pkt := MakeControlPacket(p, P_CONTROL_V1, 0)
	pkt.SetPid(42)
	if !pkt.hasPid {
		t.Fatal("hasPid should be true after SetPid")
	}
	if pkt.pid != 42 {
		t.Fatalf("pid = %d, want 42", pkt.pid)
	}
}

func TestControlPacketBytesNoAck(t *testing.T) {
	p := mockPeer()
	pkt := MakeControlPacket(p, P_CONTROL_V1, 0)
	pkt.SetPid(1)
	pkt.payload = []byte("test payload")

	data := pkt.Bytes(nil)
	if len(data) == 0 {
		t.Fatal("Bytes() returned empty")
	}

	// First byte: opcode|kid
	head := data[0]
	gotType := PacketType(head >> P_OPCODE_SHIFT)
	gotKid := head & P_KEY_ID_MASK
	if gotType != P_CONTROL_V1 {
		t.Fatalf("type = %v, want P_CONTROL_V1", gotType)
	}
	if gotKid != 0 {
		t.Fatalf("kid = %d, want 0", gotKid)
	}

	// Bytes 1-8: session ID
	if !bytes.Equal(data[1:9], p.localId[:]) {
		t.Fatal("session ID mismatch in wire bytes")
	}

	// Byte 9: ack count (0)
	if data[9] != 0 {
		t.Fatalf("ack count = %d, want 0", data[9])
	}

	// When ack_count=0, no remote_id is written
	// Bytes 10-13: PID (=1)
	if data[10] != 0 || data[11] != 0 || data[12] != 0 || data[13] != 1 {
		t.Fatalf("PID encoding wrong: %v", data[10:14])
	}

	// Rest: payload
	if !bytes.Equal(data[14:], []byte("test payload")) {
		t.Fatalf("payload mismatch: %q", data[14:])
	}
}

func TestControlPacketBytesWithAck(t *testing.T) {
	p := mockPeer()
	pkt := MakeControlPacket(p, P_CONTROL_V1, 0)
	pkt.SetPid(5)

	acks := []uint32{1, 2, 3}
	data := pkt.Bytes(acks)

	// Byte 9: ack count
	if data[9] != 3 {
		t.Fatalf("ack count = %d, want 3", data[9])
	}
}

func TestParseControlPacketRoundtrip(t *testing.T) {
	p := mockPeer()
	pkt := MakeControlPacket(p, P_CONTROL_V1, 2)
	pkt.SetPid(100)
	pkt.payload = []byte("roundtrip test data")

	data := pkt.Bytes(nil)

	// Parse it back
	reader := bytes.NewReader(data[1:]) // skip opcode byte
	gotType := PacketType(data[0] >> P_OPCODE_SHIFT)
	gotKid := data[0] & P_KEY_ID_MASK

	parsed, err := ParseControlPacket(gotType, gotKid, reader, p)
	if err != nil {
		t.Fatal("ParseControlPacket failed:", err)
	}

	if parsed.t != P_CONTROL_V1 {
		t.Fatalf("type = %v, want P_CONTROL_V1", parsed.t)
	}
	if parsed.kid != 2 {
		t.Fatalf("kid = %d, want 2", parsed.kid)
	}
	if parsed.pid != 100 {
		t.Fatalf("pid = %d, want 100", parsed.pid)
	}
	if !bytes.Equal(parsed.payload, pkt.payload) {
		t.Fatalf("payload mismatch: %q vs %q", parsed.payload, pkt.payload)
	}
}

func TestParseControlPacketACK(t *testing.T) {
	// ACK packets have no PID
	p := mockPeer()
	pkt := MakeControlPacket(p, P_ACK_V1, 0)
	// ACK has no payload and no PID

	data := pkt.Bytes([]uint32{42})

	reader := bytes.NewReader(data[1:])
	parsed, err := ParseControlPacket(P_ACK_V1, 0, reader, p)
	if err != nil {
		t.Fatal("ParseControlPacket ACK failed:", err)
	}
	if parsed.hasPid {
		t.Fatal("ACK should not have PID")
	}
}

func TestParseControlPacketTruncated(t *testing.T) {
	// Only 3 bytes — too short for session ID
	reader := bytes.NewReader([]byte{0x01, 0x02, 0x03})
	_, err := ParseControlPacket(P_CONTROL_V1, 0, reader, mockPeer())
	if err == nil {
		t.Fatal("expected error for truncated packet")
	}
}

func TestIsControlPacket(t *testing.T) {
	controlTypes := []PacketType{
		P_CONTROL_HARD_RESET_CLIENT_V1, P_CONTROL_HARD_RESET_SERVER_V1,
		P_CONTROL_SOFT_RESET_V1, P_CONTROL_V1, P_ACK_V1,
		P_CONTROL_HARD_RESET_CLIENT_V2, P_CONTROL_HARD_RESET_SERVER_V2,
	}
	for _, pt := range controlTypes {
		if !IsControlPacket(pt) {
			t.Errorf("IsControlPacket(%v) = false, want true", pt)
		}
	}

	dataTypes := []PacketType{0, P_DATA_V1, P_DATA_V2}
	for _, pt := range dataTypes {
		if IsControlPacket(pt) {
			t.Errorf("IsControlPacket(%v) = true, want false", pt)
		}
	}

	// Out of range
	if IsControlPacket(10) {
		t.Error("IsControlPacket(10) = true, want false")
	}
}

func TestPacketTypeString(t *testing.T) {
	s := P_DATA_V1.String()
	if s == "" {
		t.Fatal("PacketType.String() returned empty")
	}
}
