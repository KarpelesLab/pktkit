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

	buf := bytes.NewReader(data)
	buf.ReadByte()

	// check hmac
	if p.opts.AuthHashSize != 0 {
		// remove hash from beginning of packet
		hash := make([]byte, p.opts.AuthHashSize)
		_, err = io.ReadFull(buf, hash)
		if err != nil {
			return err
		}

		// compute hmac
		h := hmac.New(p.opts.AuthHashNew, p.keys.HmacDecrypt[:p.opts.AuthHashSize])

		pos, _ := buf.Seek(0, io.SeekCurrent)
		buf.WriteTo(h)
		buf.Seek(pos, io.SeekStart)

		if !hmac.Equal(hash, h.Sum(nil)) {
			log.Printf("[ovpn] invalid hmac in packet from %v - packet ignored", p)
			return nil
		}
	}

	var pid uint32
	pid_read_done := false

	// handle encryption
	if p.opts.CipherCrypto != 0 {
		if p.opts.CipherBlockDecrypt == nil {
			p.opts.CipherBlockDecrypt, err = aes.NewCipher(p.keys.CipherDecrypt[:(p.opts.CipherSize / 8)])
			if err != nil {
				return err
			}
		}

		switch p.opts.CipherBlock {
		case CBC:
			// block size = 128 bits / 16 bytes, IV is prefixed to block
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
			// we use a single instance of GCM over time
			if p.opts.DecryptAEAD == nil {
				p.opts.DecryptAEAD, err = cipher.NewGCM(p.opts.CipherBlockDecrypt)
				if err != nil {
					return err
				}
			}

			// read explicit iv part
			iv := make([]byte, 4)
			_, err = io.ReadFull(buf, iv)
			if err != nil {
				return err
			}

			data_ad := make([]byte, 4)
			copy(data_ad, iv)

			binary.Read(bytes.NewReader(data_ad), binary.BigEndian, &pid)
			pid_read_done = true

			// append to iv implicit data
			iv = append(iv, p.keys.HmacDecrypt[:p.opts.DecryptAEAD.NonceSize()-len(iv)]...)

			pos, _ := buf.Seek(0, io.SeekCurrent)
			data = data[pos:]

			// openvpn will put tag at beginning of string, but golang requires tag to be appended
			tag := data[0:16]
			data = append(data[16:], tag...)

			// open
			data, err = p.opts.DecryptAEAD.Open(data[:0], iv, data, data_ad)
			if err != nil {
				log.Printf("[ovpn] failed to read encrypted data: GCM error %v", err)
				return nil
			}

			// reset reader
			buf = bytes.NewReader(data)
		default:
			log.Printf("[ovpn] unsupported cipher block method %v, packet ignored", p.opts.CipherBlock)
			return nil
		}
	}

	if !pid_read_done {
		err = binary.Read(buf, binary.BigEndian, &pid)
		if err != nil {
			return err
		}
	}

	// replay protection
	if !p.replayWindow.check(pid) {
		return nil // duplicate or too old
	}

	compress, _ := buf.ReadByte()
	switch compress {
	case 0x66: // lzo
		return errors.New("lzo compression not supported")
	case 0x69: // lz4
		return errors.New("lz4 compression not supported")
	case 0xfa: // no compression
		// nothing
	default:
		return errors.New("unsupported compression format")
	}

	pos, _ := buf.Seek(0, io.SeekCurrent)

	// re-calculate data here
	data = data[pos:]

	if len(data) == len(OPENVPN_PING) {
		if bytes.Equal(OPENVPN_PING, data) {
			return nil
		}
	}

	// deliver decrypted payload
	if p.layer == 2 {
		if p.onL2Packet != nil {
			p.onL2Packet(pktkit.Frame(data))
		}
		return nil
	}

	// layer 3 (tun mode)
	if p.onL3Packet != nil {
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
	// we need to make a P_DATA_V1 packet
	// first we need a unique packet id
	pid := atomic.AddUint32(&p.pid, 1)
	pidBin := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(pidBin, pid)

	// data to prefix (can be compression info or packet id)
	var pfx []byte

	if p.opts.Compression != "" {
		// need to prefix compression info
		// 0xfa = no compression
		pfx = append(pfx, 0xfa)
	}
	var err error

	// handle encryption
	if p.opts.CipherCrypto != 0 {
		if p.opts.CipherBlockEncrypt == nil {
			p.opts.CipherBlockEncrypt, err = aes.NewCipher(p.keys.CipherEncrypt[:(p.opts.CipherSize / 8)])
			if err != nil {
				return err
			}
		}

		switch p.opts.CipherBlock {
		case CBC:
			// block size = 128 bits / 16 bytes, IV is prefixed to block
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

			// prefix iv
			data = append(iv, data...)
		case GCM:
			// we use a single instance of GCM over time
			if p.opts.EncryptAEAD == nil {
				p.opts.EncryptAEAD, err = cipher.NewGCM(p.opts.CipherBlockEncrypt)
				if err != nil {
					return err
				}
			}

			// make explicit iv part
			iv := make([]byte, 4)
			copy(iv, pidBin)

			// append to iv implicit data
			iv = append(iv, p.keys.HmacEncrypt[:p.opts.EncryptAEAD.NonceSize()-len(iv)]...)

			if pfx != nil {
				data = append(pfx, data...)
			}

			// seal
			data = p.opts.EncryptAEAD.Seal(data[:0], iv, data, pidBin)

			// openvpn will want tag at beginning of string, but golang requires tag to be appended
			tag := data[len(data)-16:]
			data = append(tag, data[:len(data)-16]...)

			// prefix pid
			data = append(pidBin, data...)
		default:
			log.Printf("[ovpn] unsupported cipher block method %v, packet ignored", p.opts.CipherBlock)
			return nil
		}
	}

	// add packet type (kid=0)
	id := byte(P_DATA_V1) << P_OPCODE_SHIFT

	// add hmac
	if p.opts.AuthHashSize != 0 {
		// compute hmac
		h := hmac.New(p.opts.AuthHashNew, p.keys.HmacEncrypt[:p.opts.AuthHashSize])
		h.Write(data)

		hash := h.Sum(nil)

		// prepend
		data = append(append([]byte{id}, hash[:p.opts.AuthHashSize]...), data...)
	} else {
		// only prepend packet code
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
