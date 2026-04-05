package ovpn

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/KarpelesLab/pktkit"
)

type PeerConnection interface {
	SetPeer(p *Peer)
	Close()
	Send(pkt []byte) error
}

type Peer struct {
	c    PeerConnection
	key  Addr
	o    *OVpn
	conn *PeerConn

	peerId, localId [8]byte

	// layer: 2 = tap (Ethernet frames), 3 = tun (IP packets)
	layer byte

	tlsConn *tls.Conn

	IdleTimer uint32
	closeOnce sync.Once

	opts *Options
	keys *PeerKeys

	// replay protection
	replayWindow *window

	// outgoing next packet id
	pid uint32

	// packet delivery callbacks, set by the adapter after authentication
	onL3Packet func(pktkit.Packet)
	onL2Packet func(pktkit.Frame)

	// reliability related variables
	ctrlLock    sync.Mutex
	ctrlOut     map[uint32]*ControlPacket
	ctrlIn      map[uint32]*ControlPacket
	ctrlAck     []uint32
	ctrlInCntr  uint32 // id of latest received packet
	ctrlOutCntr uint32
}

func NewPeer(c PeerConnection, o *OVpn, k Addr) *Peer {
	res := &Peer{
		c:            c,
		key:          k,
		o:            o,
		ctrlIn:       make(map[uint32]*ControlPacket),
		ctrlOut:      make(map[uint32]*ControlPacket),
		replayWindow: newWindow(),
	}
	res.conn = MakePeerConn(res)
	res.tlsConn = tls.Server(res.conn, o.tlsConfig)

	go res.tlsThread()

	c.SetPeer(res)
	return res
}

func (p *Peer) handlePacket(data []byte) {
	atomic.StoreUint32(&p.IdleTimer, 0)

	err := p.handlePacketError(data)

	if err != nil {
		log.Printf("[ovpn] An error happened while handling packet from %v: %v", p, err)
		p.Close()
	}
}

func (p *Peer) handlePacketError(data []byte) error {
	buf := bytes.NewReader(data)

	head, err := buf.ReadByte()
	if err != nil {
		return err
	}

	t := PacketType(head >> P_OPCODE_SHIFT)
	kid := head & P_KEY_ID_MASK

	if IsControlPacket(t) {
		// this is a control packet
		pkt, err := ParseControlPacket(t, kid, buf, p)
		if err != nil {
			return err
		}

		if pkt.t == P_ACK_V1 {
			// received ACK - ParseControlPacket already handled it, so no need to do anything here
			return nil
		}

		err = p.handleControlPacket(pkt)
		if err != nil {
			return err
		}
		return p.SendAck()
	}

	switch t {
	case P_DATA_V1:
		return p.handleData(data)
	}
	log.Printf("[ovpn] Received unhandled packet of %d bytes (type=%s kid=%d) from %s\n%s", len(data), t, kid, p.String(), hex.Dump(data))
	return nil
}

func (p *Peer) handleData(data []byte) (err error) {
	if p.opts == nil {
		return errors.New("this stream is not ready for data transmission")
	}

	// Lazily initialize cipher block
	if p.opts.CipherCrypto != 0 && p.opts.CipherBlockDecrypt == nil {
		p.opts.CipherBlockDecrypt, err = aes.NewCipher(p.keys.CipherDecrypt[:(p.opts.CipherSize / 8)])
		if err != nil {
			return err
		}
	}

	// Fast path for GCM (most common modern cipher)
	if p.opts.CipherCrypto != 0 && p.opts.CipherBlock == GCM && p.opts.AuthHashSize == 0 {
		return p.handleDataGCM(data)
	}

	return p.handleDataGeneric(data)
}

// handleDataGCM is the optimized GCM decrypt path with minimal allocations.
// Wire format: [opcode:1][pid:4][tag:16][ciphertext...]
func (p *Peer) handleDataGCM(data []byte) error {
	// Minimum: opcode(1) + pid(4) + tag(16) = 21
	if len(data) < 21 {
		return errors.New("GCM packet too short")
	}

	if p.opts.DecryptAEAD == nil {
		var err error
		p.opts.DecryptAEAD, err = cipher.NewGCM(p.opts.CipherBlockDecrypt)
		if err != nil {
			return err
		}
	}

	// Parse PID from bytes 1-5
	pid := binary.BigEndian.Uint32(data[1:5])

	// Build nonce: [pid:4][implicit_iv from HmacDecrypt]
	var nonce [12]byte
	copy(nonce[0:4], data[1:5])
	copy(nonce[4:], p.keys.HmacDecrypt[:p.opts.DecryptAEAD.NonceSize()-4])

	// AD is the 4-byte PID
	ad := data[1:5]

	// OpenVPN wire format has tag before ciphertext: [tag:16][ct...]
	// Go's GCM Open expects: [ct...][tag:16]
	// Rearrange in-place.
	payload := data[5:] // [tag:16][ct...]
	ctLen := len(payload) - 16
	if ctLen < 0 {
		return errors.New("GCM payload too short")
	}

	// Swap tag to end: copy tag aside, shift ct left, put tag at end
	var tag [16]byte
	copy(tag[:], payload[0:16])
	copy(payload[0:ctLen], payload[16:])
	copy(payload[ctLen:], tag[:])

	// Decrypt in-place
	plaintext, err := p.opts.DecryptAEAD.Open(payload[:0], pktkit.NoescapeBytes(unsafe.Pointer(&nonce), 12), payload, ad)
	if err != nil {
		return nil // GCM auth failure — drop silently
	}

	// Replay protection
	if !p.replayWindow.check(pid) {
		return nil
	}

	// Parse compression byte
	if len(plaintext) < 1 {
		return nil
	}
	switch plaintext[0] {
	case 0xfa: // no compression
		plaintext = plaintext[1:]
	case 0x66:
		return errors.New("lzo compression not supported")
	case 0x69:
		return errors.New("lz4 compression not supported")
	default:
		return errors.New("unsupported compression format")
	}

	// Check for ping
	if len(plaintext) == len(OPENVPN_PING) && bytes.Equal(OPENVPN_PING, plaintext) {
		return nil
	}

	// Deliver decrypted payload
	if p.layer == 2 {
		if p.onL2Packet != nil {
			p.onL2Packet(pktkit.Frame(plaintext))
		}
	} else if p.onL3Packet != nil {
		p.onL3Packet(pktkit.Packet(plaintext))
	}
	return nil
}

// handleDataGeneric handles CBC and other non-GCM cipher modes (original path).
func (p *Peer) handleDataGeneric(data []byte) (err error) {
	buf := bytes.NewReader(data)
	buf.ReadByte()

	// check hmac
	if p.opts.AuthHashSize != 0 {
		hash := make([]byte, p.opts.AuthHashSize)
		_, err = io.ReadFull(buf, hash)
		if err != nil {
			return err
		}

		h := hmac.New(p.opts.AuthHashNew, p.keys.HmacDecrypt[:p.opts.AuthHashSize])
		pos, _ := buf.Seek(0, io.SeekCurrent)
		buf.WriteTo(h)
		buf.Seek(pos, io.SeekStart)

		if !hmac.Equal(hash, h.Sum(nil)) {
			return nil
		}
	}

	var pid uint32
	pid_read_done := false

	if p.opts.CipherCrypto != 0 {
		switch p.opts.CipherBlock {
		case CBC:
			iv := make([]byte, 16)
			_, err = io.ReadFull(buf, iv)
			if err != nil {
				return err
			}

			dec := cipher.NewCBCDecrypter(p.opts.CipherBlockDecrypt, iv)
			pos, _ := buf.Seek(0, io.SeekCurrent)
			data = data[pos:]
			dec.CryptBlocks(data, data)
			data = PKCS5Trimming(data)
			buf = bytes.NewReader(data)
		case GCM:
			if p.opts.DecryptAEAD == nil {
				p.opts.DecryptAEAD, err = cipher.NewGCM(p.opts.CipherBlockDecrypt)
				if err != nil {
					return err
				}
			}

			iv := make([]byte, 4)
			_, err = io.ReadFull(buf, iv)
			if err != nil {
				return err
			}

			data_ad := make([]byte, 4)
			copy(data_ad, iv)

			binary.Read(bytes.NewReader(data_ad), binary.BigEndian, &pid)
			pid_read_done = true

			iv = append(iv, p.keys.HmacDecrypt[:p.opts.DecryptAEAD.NonceSize()-len(iv)]...)

			pos, _ := buf.Seek(0, io.SeekCurrent)
			data = data[pos:]

			tag := data[0:16]
			data = append(data[16:], tag...)

			data, err = p.opts.DecryptAEAD.Open(data[:0], iv, data, data_ad)
			if err != nil {
				return nil
			}

			buf = bytes.NewReader(data)
		default:
			return nil
		}
	}

	if !pid_read_done {
		err = binary.Read(buf, binary.BigEndian, &pid)
		if err != nil {
			return err
		}
	}

	if !p.replayWindow.check(pid) {
		return nil
	}

	compress, _ := buf.ReadByte()
	switch compress {
	case 0x66:
		return errors.New("lzo compression not supported")
	case 0x69:
		return errors.New("lz4 compression not supported")
	case 0xfa:
	default:
		return errors.New("unsupported compression format")
	}

	pos, _ := buf.Seek(0, io.SeekCurrent)
	data = data[pos:]

	if len(data) == len(OPENVPN_PING) && bytes.Equal(OPENVPN_PING, data) {
		return nil
	}

	if p.layer == 2 {
		if p.onL2Packet != nil {
			p.onL2Packet(pktkit.Frame(data))
		}
	} else if p.onL3Packet != nil {
		p.onL3Packet(pktkit.Packet(data))
	}
	return nil
}

func (p *Peer) handleControlPacket(pkt *ControlPacket) error {
	p.ctrlLock.Lock()
	defer p.ctrlLock.Unlock()

	// store packet in queue, then process it
	if pkt.pid < p.ctrlInCntr {
		// packet has already been processed
		return nil
	}

	if pkt.pid > p.ctrlInCntr+TLS_RELIABLE_N_REC_BUFFERS {
		// packet too far in stream
		return errors.New("rejecting packet because pid looks invalid")
	}

	// first let's check if not already in queue
	_, ok := p.ctrlIn[pkt.pid]
	if !ok {
		p.ctrlIn[pkt.pid] = pkt
	}

	// run execution queue
	for {
		pkt, ok = p.ctrlIn[p.ctrlInCntr]
		if !ok {
			if len(p.ctrlIn) > TLS_RELIABLE_N_REC_BUFFERS {
				return errors.New("received too many packets, dropping connection")
			}
			return nil
		}

		delete(p.ctrlIn, p.ctrlInCntr)
		p.ctrlInCntr += 1

		err := p.handleControlPacketLocked(pkt)
		if err != nil {
			return err
		}
	}
}

func (p *Peer) handleControlPacketLocked(pkt *ControlPacket) error {
	switch pkt.t {
	case P_CONTROL_HARD_RESET_CLIENT_V2:
		// take note of pkt.payload as peerId
		p.peerId = pkt.sid

		// generate local session id
		_, err := rand.Read(p.localId[:])
		if err != nil {
			return err
		}

		res := MakeControlPacket(p, P_CONTROL_HARD_RESET_SERVER_V2, 0)

		return p.SendPacketLocked(res)
	case P_CONTROL_V1:
		p.conn.readChan <- pkt.payload
		return nil
	}

	return errors.New("this method is still TODO")
}

func (p *Peer) SendData(data []byte) error {
	if p.opts == nil {
		return errors.New("this stream is not ready for data transmission")
	}

	var err error

	// Lazily initialize cipher block
	if p.opts.CipherCrypto != 0 && p.opts.CipherBlockEncrypt == nil {
		p.opts.CipherBlockEncrypt, err = aes.NewCipher(p.keys.CipherEncrypt[:(p.opts.CipherSize / 8)])
		if err != nil {
			return err
		}
	}

	// Dispatch to optimized path per cipher mode
	if p.opts.CipherCrypto != 0 && p.opts.CipherBlock == GCM {
		return p.sendDataGCM(data)
	}
	return p.sendDataGeneric(data)
}

// sendDataGCM is the optimized GCM encrypt path with minimal allocations.
// Wire format: [opcode:1][pid:4][tag:16][ciphertext...]
// The plaintext is [compression:1][payload...], encrypted with nonce=[pid:4][implicit_iv:8].
func (p *Peer) sendDataGCM(data []byte) error {
	if p.opts.EncryptAEAD == nil {
		var err error
		p.opts.EncryptAEAD, err = cipher.NewGCM(p.opts.CipherBlockEncrypt)
		if err != nil {
			return err
		}
	}

	aead := p.opts.EncryptAEAD

	pid := atomic.AddUint32(&p.pid, 1)

	// Build nonce: [pid:4][implicit_iv from HmacEncrypt]
	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], pid)
	copy(nonce[4:], p.keys.HmacEncrypt[:aead.NonceSize()-4])

	// AD is the 4-byte PID
	var ad [4]byte
	binary.BigEndian.PutUint32(ad[0:4], pid)

	// Build plaintext: [compression_byte][payload]
	hasCompression := p.opts.Compression != ""
	ptLen := len(data)
	if hasCompression {
		ptLen++
	}

	// Output layout: [opcode:1][pid:4][tag:16][ciphertext(ptLen)...]
	// Total = 1 + 4 + 16 + ptLen = 21 + ptLen
	outLen := 1 + 4 + 16 + ptLen
	out, handle := pktkit.AllocBuffer(outLen)

	// Opcode
	out[0] = byte(P_DATA_V1) << P_OPCODE_SHIFT

	// PID
	copy(out[1:5], ad[:])

	// Assemble plaintext in a contiguous region so Seal can read it.
	// We use the area after the tag in `out` as scratch for the plaintext,
	// since Seal will overwrite it with ciphertext of the same length.
	pt := out[21:21] // len=0, cap has room for ptLen
	if hasCompression {
		pt = append(pt, 0xfa)
	}
	pt = append(pt, data...)

	// Seal into out[21:] (ciphertext), appending the tag at the end.
	// Go's GCM Seal produces: ciphertext || tag
	sealed := aead.Seal(out[21:21], pktkit.NoescapeBytes(unsafe.Pointer(&nonce), 12), pt, ad[:])

	// OpenVPN wants tag BEFORE ciphertext. sealed = ciphertext || tag (in out[21:]).
	// We need to rearrange to out[5:] = tag || ciphertext.
	sealedLen := len(sealed) // = ptLen + 16
	ctLen := sealedLen - 16

	// Copy tag (last 16 bytes of sealed) to out[5:21]
	copy(out[5:21], out[21+ctLen:21+sealedLen])
	// Ciphertext is already at out[21:21+ctLen], which is correct position.

	err := p.Send(out[:outLen])
	pktkit.FreeBuffer(handle)
	return err
}

// sendDataGeneric handles CBC and other non-GCM cipher modes (original path).
func (p *Peer) sendDataGeneric(data []byte) error {
	pid := atomic.AddUint32(&p.pid, 1)
	pidBin := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(pidBin, pid)

	var pfx []byte
	if p.opts.Compression != "" {
		pfx = append(pfx, 0xfa)
	}
	var err error

	if p.opts.CipherCrypto != 0 {
		switch p.opts.CipherBlock {
		case CBC:
			iv := make([]byte, 16)
			_, err = io.ReadFull(rand.Reader, iv)
			if err != nil {
				return err
			}

			enc := cipher.NewCBCEncrypter(p.opts.CipherBlockEncrypt, iv)
			if pfx != nil {
				data = append(append(pfx, pidBin...), data...)
				pfx = nil
			}
			data = PKCS5Padding(data, 16)
			enc.CryptBlocks(data, data)
			data = append(iv, data...)
		default:
			log.Printf("[ovpn] unsupported cipher block method %v, packet ignored", p.opts.CipherBlock)
			return nil
		}
	}

	id := byte(P_DATA_V1) << P_OPCODE_SHIFT

	if p.opts.AuthHashSize != 0 {
		h := hmac.New(p.opts.AuthHashNew, p.keys.HmacEncrypt[:p.opts.AuthHashSize])
		h.Write(data)
		hash := h.Sum(nil)
		data = append(append([]byte{id}, hash[:p.opts.AuthHashSize]...), data...)
	} else {
		data = append([]byte{id}, data...)
	}

	return p.Send(data)
}

func (p *Peer) SendPacket(pkt *ControlPacket) error {
	p.ctrlLock.Lock()
	defer p.ctrlLock.Unlock()

	return p.SendPacketLocked(pkt)
}

func (p *Peer) SendPacketLocked(pkt *ControlPacket) error {
	pkt.SetPid(p.ctrlOutCntr)
	p.ctrlOut[p.ctrlOutCntr] = pkt
	p.ctrlOutCntr += 1

	err := p.Send(pkt.Bytes(p.ctrlAck))
	if err != nil {
		return err
	}
	p.ctrlAck = []uint32{}

	return nil
}

func (p *Peer) GotAck(msgid uint32) {
	p.ctrlLock.Lock()
	defer p.ctrlLock.Unlock()

	delete(p.ctrlOut, msgid)
}

func (p *Peer) AppendAck(msgid uint32) {
	p.ctrlLock.Lock()
	defer p.ctrlLock.Unlock()

	p.ctrlAck = append(p.ctrlAck, msgid)
}

func (p *Peer) SendAck() error {
	p.ctrlLock.Lock()
	defer p.ctrlLock.Unlock()

	// send ACK packet
	if len(p.ctrlAck) == 0 {
		return nil
	}

	pkt := MakeControlPacket(p, P_ACK_V1, 0)
	p.Send(pkt.Bytes(p.ctrlAck))
	p.ctrlAck = []uint32{}

	return nil
}

func (p *Peer) Send(pkt []byte) error {
	return p.c.Send(pkt)
}

func (p *Peer) Close() {
	p.closeOnce.Do(func() {
		p.conn.closed = true
		close(p.conn.readChan)
		p.c.Close()
	})
	p.Unregister()
}

func (p *Peer) Key() Addr {
	return p.key
}

func (p *Peer) Unregister() {
	p.o.peersLock.Lock()
	defer p.o.peersLock.Unlock()
	delete(p.o.peers, p.Key())

	// notify adapter of peer disconnect
	if p.o.adapter != nil {
		p.o.adapter.onPeerDisconnected(p.key)
	}
}

func (p *Peer) String() string {
	return p.key.String()
}
