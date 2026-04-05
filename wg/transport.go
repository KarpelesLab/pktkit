// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wg

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/KarpelesLab/pktkit"
)

// noescapeSlice returns a []byte pointing to the given array without causing
// escape analysis to move the array to the heap.
func noescapeSlice(b *[chacha20poly1305.NonceSize]byte) []byte {
	return pktkit.NoescapeBytes(unsafe.Pointer(b), chacha20poly1305.NonceSize)
}

// processDataPacket decrypts an incoming type-4 transport data packet. It looks
// up the keypair by receiver index, checks for replay, and decrypts the payload.
// Empty payloads are returned as PacketKeepalive.
func (h *Handler) processDataPacket(data []byte) (PacketResult, error) {
	if len(data) < messageTransportHeaderSize {
		return PacketResult{}, fmt.Errorf("data packet too short: %d", len(data))
	}

	msgType := binary_le_uint32(data[0:4])
	if msgType != messageTransportType {
		return PacketResult{}, fmt.Errorf("invalid message type: %d (expected %d)", msgType, messageTransportType)
	}

	receiverIdx := binary_le_uint32(data[4:8])
	counter := binary_le_uint64(data[8:16])

	// Find keypair
	h.keypairsMutex.RLock()
	kp, exists := h.keypairs[receiverIdx]
	h.keypairsMutex.RUnlock()

	if !exists {
		return PacketResult{}, fmt.Errorf("no keypair for receiver index: %d", receiverIdx)
	}

	// Reject expired keypairs (forward secrecy)
	if now().Sub(kp.created) > RejectAfterTime {
		return PacketResult{}, fmt.Errorf("keypair expired")
	}

	// Create nonce from counter (stack-allocated, does not escape).
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Check for replay
	if kp.replayFilter.CheckReplay(counter) {
		return PacketResult{}, fmt.Errorf("replay detected for counter: %d", counter)
	}

	// Decrypt in-place
	ciphertext := data[16:]
	plaintext, err := kp.receive.Open(ciphertext[:0], noescapeSlice(&nonce), ciphertext, nil)
	if err != nil {
		return PacketResult{}, fmt.Errorf("decrypt failed: %w", err)
	}

	// Peer key is stored directly on the keypair — O(1) lookup.
	peerKey := kp.peerKey

	// Update session last received time
	h.sessionsMutex.RLock()
	if sess, exists := h.sessions[peerKey]; exists {
		sess.mutex.Lock()
		sess.lastReceived = now()
		sess.mutex.Unlock()
	}
	h.sessionsMutex.RUnlock()

	resultType := PacketTransportData
	if len(plaintext) == 0 {
		resultType = PacketKeepalive
	}

	return PacketResult{
		Type:    resultType,
		Data:    plaintext,
		PeerKey: peerKey,
	}, nil
}

// EncryptedSize returns the total wire size of an encrypted WireGuard packet
// for the given plaintext length.
func EncryptedSize(plaintextLen int) int {
	return messageTransportHeaderSize + plaintextLen + chacha20poly1305.Overhead
}

// EncryptTo encrypts data for a peer into the provided buffer dst.
// dst must be at least EncryptedSize(len(data)) bytes.
// Returns the number of bytes written, or an error.
//
// When err is ErrRekeyRequired the data was still encrypted successfully;
// the caller should send the packet and then initiate a new handshake.
//
// This is the zero-allocation encrypt path. The caller is responsible for
// providing (and recycling) the buffer.
func (h *Handler) EncryptTo(dst []byte, data []byte, peerKey NoisePublicKey) (int, error) {
	needed := EncryptedSize(len(data))
	if len(dst) < needed {
		return 0, fmt.Errorf("dst too small: need %d, got %d", needed, len(dst))
	}

	// Find session
	h.sessionsMutex.RLock()
	sess, exists := h.sessions[peerKey]
	if !exists {
		h.sessionsMutex.RUnlock()
		return 0, fmt.Errorf("no session for peer")
	}
	h.sessionsMutex.RUnlock()

	// Get current keypair — single now() call for all time checks.
	n := now()
	sess.mutex.Lock()
	kp := sess.keypairCurrent
	if kp == nil {
		sess.mutex.Unlock()
		return 0, fmt.Errorf("no current keypair for peer")
	}
	kpAge := n.Sub(kp.created)
	if kpAge > RejectAfterTime {
		sess.mutex.Unlock()
		return 0, fmt.Errorf("keypair expired: initiate new handshake")
	}
	remoteIndex := kp.remoteIndex
	sess.lastSent = n
	sess.mutex.Unlock()

	// Increment per-keypair counter (starts at 0)
	counter := atomic.AddUint64(&kp.sendCounter, 1) - 1
	if counter >= RejectAfterMessages {
		return 0, fmt.Errorf("keypair message limit exceeded: initiate new handshake")
	}

	// Create nonce from counter (stack-allocated, does not escape).
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Write header
	binary_le_put_uint32(dst[0:4], messageTransportType)
	binary_le_put_uint32(dst[4:8], remoteIndex)
	binary_le_put_uint64(dst[8:16], counter)

	// Seal directly into dst after the header.
	kp.send.Seal(dst[messageTransportHeaderSize:messageTransportHeaderSize], noescapeSlice(&nonce), data, nil)

	// Signal rekey if approaching limits
	if counter >= RekeyAfterMessages || kpAge >= RekeyAfterTime {
		return needed, ErrRekeyRequired
	}

	return needed, nil
}

// encryptDataPacket encrypts data for transmission to a peer and returns a
// complete type-4 transport packet. Pass empty data to generate a keepalive.
//
// Returns ErrRekeyRequired alongside a valid packet when the keypair has
// exceeded RekeyAfterTime or RekeyAfterMessages. The caller should send
// the packet and then initiate a new handshake.
func (h *Handler) encryptDataPacket(data []byte, peerKey NoisePublicKey) ([]byte, error) {
	result := make([]byte, EncryptedSize(len(data)))
	n, err := h.EncryptTo(result, data, peerKey)
	if err != nil && err != ErrRekeyRequired {
		return nil, err
	}
	return result[:n], err
}

// EncryptPooled encrypts data for a peer using a buffer from the global packet
// pool. Returns the encrypted packet and a pool handle. The caller MUST call
// pktkit.FreeBuffer(handle) after the packet has been sent (e.g. after WriteTo).
//
// This is the zero-allocation encrypt path for callers that can manage buffer
// lifetimes (such as the WireGuard Server).
func (h *Handler) EncryptPooled(data []byte, peerKey NoisePublicKey) ([]byte, *[]byte, error) {
	needed := EncryptedSize(len(data))
	buf, handle := pktkit.AllocBuffer(needed)
	n, err := h.EncryptTo(buf, data, peerKey)
	if err != nil && err != ErrRekeyRequired {
		pktkit.FreeBuffer(handle)
		return nil, nil, err
	}
	return buf[:n], handle, err
}
