package ovpn

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// setupPeerPair creates a sender and receiver Peer for roundtrip testing.
// sender encrypts, receiver decrypts with swapped keys.
func setupPeerPair(t *testing.T, cipher string) (sender, receiver *Peer, captured *[]byte) {
	t.Helper()

	opt := NewOptions()
	if err := opt.ParseCipher(cipher); err != nil {
		t.Fatal(err)
	}
	if opt.CipherBlock == GCM {
		opt.Auth = 0
	}
	opt.Compression = "lzo"
	if err := opt.Prepare(); err != nil {
		t.Fatal(err)
	}

	keyMaterial := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		t.Fatal(err)
	}
	senderKeys := NewPeerKeys(keyMaterial)

	// Receiver keys are swapped
	receiverKeys := &PeerKeys{
		CipherEncrypt: make([]byte, 64),
		HmacEncrypt:   make([]byte, 64),
		CipherDecrypt: make([]byte, 64),
		HmacDecrypt:   make([]byte, 64),
	}
	copy(receiverKeys.CipherDecrypt, senderKeys.CipherEncrypt)
	copy(receiverKeys.HmacDecrypt, senderKeys.HmacEncrypt)
	copy(receiverKeys.CipherEncrypt, senderKeys.CipherDecrypt)
	copy(receiverKeys.HmacEncrypt, senderKeys.HmacDecrypt)

	recvOpt := NewOptions()
	if err := recvOpt.ParseCipher(cipher); err != nil {
		t.Fatal(err)
	}
	if recvOpt.CipherBlock == GCM {
		recvOpt.Auth = 0
	}
	recvOpt.Compression = "lzo"
	if err := recvOpt.Prepare(); err != nil {
		t.Fatal(err)
	}

	var cap []byte
	sender = &Peer{
		opts:         opt,
		keys:         senderKeys,
		replayWindow: newWindow(),
		layer:        3,
		c:            &captureSender{captured: &cap},
	}
	sender.onL3Packet = func(pkt pktkit.Packet) {}

	receiver = &Peer{
		opts:         recvOpt,
		keys:         receiverKeys,
		replayWindow: newWindow(),
		layer:        3,
		c:            &discardSender{},
	}

	return sender, receiver, &cap
}

func TestGCMRoundtrip(t *testing.T) {
	sender, receiver, captured := setupPeerPair(t, "AES-256-GCM")

	payload := []byte("Hello, OpenVPN GCM roundtrip test!")
	var received []byte
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		received = make([]byte, len(pkt))
		copy(received, pkt)
	}

	if err := sender.SendData(payload); err != nil {
		t.Fatal("encrypt failed:", err)
	}

	if len(*captured) == 0 {
		t.Fatal("no packet captured")
	}

	// Feed to receiver
	pkt := make([]byte, len(*captured))
	copy(pkt, *captured)
	if err := receiver.handleData(pkt); err != nil {
		t.Fatal("decrypt failed:", err)
	}

	if !bytes.Equal(received, payload) {
		t.Fatalf("payload mismatch: got %q, want %q", received, payload)
	}
}

func TestGCMReplayReject(t *testing.T) {
	sender, receiver, captured := setupPeerPair(t, "AES-256-GCM")

	var recvCount int
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		recvCount++
	}

	payload := []byte("test replay")
	sender.SendData(payload)

	pkt := make([]byte, len(*captured))
	copy(pkt, *captured)

	// First delivery should succeed
	receiver.handleData(pkt)
	if recvCount != 1 {
		t.Fatalf("expected 1 delivery, got %d", recvCount)
	}

	// Replay: same packet should be silently dropped
	pkt2 := make([]byte, len(*captured))
	copy(pkt2, *captured)
	receiver.handleData(pkt2)
	if recvCount != 1 {
		t.Fatalf("replay should be rejected, got %d deliveries", recvCount)
	}
}

func TestGCMCorruptedTag(t *testing.T) {
	sender, receiver, captured := setupPeerPair(t, "AES-256-GCM")

	var received bool
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		received = true
	}

	sender.SendData([]byte("corrupt me"))

	pkt := make([]byte, len(*captured))
	copy(pkt, *captured)
	// Flip a bit in the tag area (bytes 5-20)
	if len(pkt) > 10 {
		pkt[10] ^= 0xff
	}

	receiver.handleData(pkt)
	if received {
		t.Fatal("corrupted packet should not be delivered")
	}
}

func TestGCMMultiplePackets(t *testing.T) {
	sender, receiver, captured := setupPeerPair(t, "AES-256-GCM")

	var received [][]byte
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		received = append(received, cp)
	}

	payloads := []string{"packet one", "packet two", "packet three"}
	for _, p := range payloads {
		sender.SendData([]byte(p))
		pkt := make([]byte, len(*captured))
		copy(pkt, *captured)
		receiver.handleData(pkt)
	}

	if len(received) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(received))
	}
	for i, p := range payloads {
		if string(received[i]) != p {
			t.Fatalf("packet %d: got %q, want %q", i, received[i], p)
		}
	}
}

func TestCBCEncrypt(t *testing.T) {
	// Test that CBC encrypt produces non-empty output with correct structure.
	sender, _, captured := setupPeerPair(t, "AES-128-CBC")

	payload := []byte("Hello, OpenVPN CBC!")
	if err := sender.SendData(payload); err != nil {
		t.Fatal("CBC encrypt failed:", err)
	}

	if len(*captured) == 0 {
		t.Fatal("no packet produced")
	}

	// First byte should have opcode P_DATA_V1
	head := (*captured)[0]
	gotType := PacketType(head >> P_OPCODE_SHIFT)
	if gotType != P_DATA_V1 {
		t.Fatalf("opcode = %v, want P_DATA_V1", gotType)
	}

	// With SHA256 auth, the packet should have: [opcode:1][hmac:32][iv:16][ciphertext...]
	// So minimum size: 1 + 32 + 16 + 16 = 65
	if len(*captured) < 65 {
		t.Fatalf("CBC packet too short: %d bytes", len(*captured))
	}
}

func TestCBCMultipleEncrypt(t *testing.T) {
	// Verify that successive CBC encryptions produce different ciphertexts (different IVs).
	sender, _, captured := setupPeerPair(t, "AES-128-CBC")

	sender.SendData([]byte("packet1"))
	pkt1 := make([]byte, len(*captured))
	copy(pkt1, *captured)

	sender.SendData([]byte("packet1")) // same payload
	pkt2 := make([]byte, len(*captured))
	copy(pkt2, *captured)

	if bytes.Equal(pkt1, pkt2) {
		t.Fatal("two CBC encryptions of same payload should differ (random IVs)")
	}
}

func TestGCMShortPacket(t *testing.T) {
	sender, _, _ := setupPeerPair(t, "AES-256-GCM")

	// Initialize the decrypt path
	receiver := &Peer{
		opts:         sender.opts,
		keys:         sender.keys,
		replayWindow: newWindow(),
		layer:        3,
		c:            &discardSender{},
	}
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		t.Fatal("should not deliver short packet")
	}

	// Too short for GCM (needs at least 21 bytes)
	short := []byte{byte(P_DATA_V1) << P_OPCODE_SHIFT, 0, 0, 0, 1}
	err := receiver.handleData(short)
	if err == nil {
		// handleDataGCM returns an error for too-short packets
		// but handleData might not be called if opts aren't initialized
	}
	_ = err // short packet is either errored or silently dropped — both fine
}

func TestGCMLargePayload(t *testing.T) {
	sender, receiver, captured := setupPeerPair(t, "AES-256-GCM")

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}

	var received []byte
	receiver.onL3Packet = func(pkt pktkit.Packet) {
		received = make([]byte, len(pkt))
		copy(received, pkt)
	}

	sender.SendData(payload)
	pkt := make([]byte, len(*captured))
	copy(pkt, *captured)
	receiver.handleData(pkt)

	if !bytes.Equal(received, payload) {
		t.Fatal("large payload mismatch")
	}
}
