// Copyright (c) VP.NET LLC. All rights reserved.
// Licensed under the MIT License.
// See LICENSE file in the project root for full license information.

package wg

import (
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// processDataPacket decrypts an incoming type-4 transport data packet. It looks
// up the keypair by receiver index, checks for replay, and decrypts the payload.
// Empty payloads are returned as PacketKeepalive.
func (h *Handler) processDataPacket(data []byte) (*PacketResult, error) {
	if len(data) < messageTransportHeaderSize {
		return nil, fmt.Errorf("data packet too short: %d", len(data))
	}

	msgType := binary_le_uint32(data[0:4])
	if msgType != messageTransportType {
		return nil, fmt.Errorf("invalid message type: %d (expected %d)", msgType, messageTransportType)
	}

	receiverIdx := binary_le_uint32(data[4:8])
	counter := binary_le_uint64(data[8:16])

	// Find keypair
	h.keypairsMutex.RLock()
	kp, exists := h.keypairs[receiverIdx]
	h.keypairsMutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no keypair for receiver index: %d", receiverIdx)
	}

	// Reject expired keypairs (forward secrecy)
	if now().Sub(kp.created) > RejectAfterTime {
		return nil, fmt.Errorf("keypair expired")
	}

	// Create nonce from counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Check for replay
	if kp.replayFilter.CheckReplay(counter) {
		return nil, fmt.Errorf("replay detected for counter: %d", counter)
	}

	// Decrypt in-place
	ciphertext := data[16:]
	plaintext, err := kp.receive.Open(ciphertext[:0], nonce[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %w", err)
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

	return &PacketResult{
		Type:    resultType,
		Data:    plaintext,
		PeerKey: peerKey,
	}, nil
}

// encryptDataPacket encrypts data for transmission to a peer and returns a
// complete type-4 transport packet. Pass empty data to generate a keepalive.
//
// Returns ErrRekeyRequired alongside a valid packet when the keypair has
// exceeded RekeyAfterTime or RekeyAfterMessages. The caller should send
// the packet and then initiate a new handshake.
func (h *Handler) encryptDataPacket(data []byte, peerKey NoisePublicKey) ([]byte, error) {
	// Find session
	h.sessionsMutex.RLock()
	sess, exists := h.sessions[peerKey]
	if !exists {
		h.sessionsMutex.RUnlock()
		return nil, fmt.Errorf("no session for peer")
	}
	h.sessionsMutex.RUnlock()

	// Get current keypair
	sess.mutex.Lock()
	kp := sess.keypairCurrent
	if kp == nil {
		sess.mutex.Unlock()
		return nil, fmt.Errorf("no current keypair for peer")
	}
	if now().Sub(kp.created) > RejectAfterTime {
		sess.mutex.Unlock()
		return nil, fmt.Errorf("keypair expired: initiate new handshake")
	}
	remoteIndex := kp.remoteIndex
	sess.lastSent = now()
	sess.mutex.Unlock()

	// Increment per-keypair counter (starts at 0)
	counter := atomic.AddUint64(&kp.sendCounter, 1) - 1

	// Reject after too many messages
	if counter >= RejectAfterMessages {
		return nil, fmt.Errorf("keypair message limit exceeded: initiate new handshake")
	}

	// Create nonce from counter
	var nonce [chacha20poly1305.NonceSize]byte
	binary_le_put_uint64(nonce[4:], counter)

	// Encrypt
	ciphertext := kp.send.Seal(nil, nonce[:], data, nil)

	// Build packet
	result := make([]byte, messageTransportHeaderSize+len(ciphertext))
	binary_le_put_uint32(result[0:4], messageTransportType)
	binary_le_put_uint32(result[4:8], remoteIndex)
	binary_le_put_uint64(result[8:16], counter)
	copy(result[messageTransportHeaderSize:], ciphertext)

	// Signal rekey if approaching limits
	if counter >= RekeyAfterMessages || now().Sub(kp.created) >= RekeyAfterTime {
		return result, ErrRekeyRequired
	}

	return result, nil
}
