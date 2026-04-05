package ovpn

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
)

type ControlPacket struct {
	t   PacketType
	kid byte
	p   *Peer

	hasPid bool
	pid    uint32

	RemoteId [8]byte

	sid     [8]byte
	payload []byte
}

func (cp *ControlPacket) Dump(rcvd bool, action string) {
	var rcvd_str string
	if rcvd {
		rcvd_str = "<-"
	} else {
		rcvd_str = "->"
	}
	log.Printf("[debug] %s Packet type %v (kid:%d) pid:%d payload:%d bytes %s", rcvd_str, cp.t, cp.kid, cp.pid, len(cp.payload), action)
}

func MakeControlPacket(p *Peer, t PacketType, kid byte) *ControlPacket {
	res := &ControlPacket{
		t:   t,
		kid: kid,
		p:   p,

		sid:      p.localId,
		RemoteId: p.peerId,

		hasPid: false,
	}

	return res
}

func ParseControlPacket(t PacketType, kid byte, buf *bytes.Reader, p *Peer) (*ControlPacket, error) {
	res := &ControlPacket{
		t:   t,
		kid: kid,
		p:   p,

		// defaults for most packets (except client reset has no remote id, and ack has no pid)
		hasPid: true,
	}

	// read sid
	_, err := io.ReadFull(buf, res.sid[:])
	if err != nil {
		return nil, err
	}

	switch t {
	case P_ACK_V1:
		res.hasPid = false
	}

	// read message packet ids (remote ack), and then this packet's id
	msgidCount, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	// confirm each packet as received by peer
	if msgidCount > 0 {
		for i := byte(0); i < msgidCount; i++ {
			var msgid uint32
			err = binary.Read(buf, binary.BigEndian, &msgid)
			if err != nil {
				return nil, err
			}
			p.GotAck(msgid)
		}

		_, err := io.ReadFull(buf, res.RemoteId[:])
		if err != nil {
			return nil, err
		}
	}

	if res.hasPid {
		// read this message's id
		err = binary.Read(buf, binary.BigEndian, &res.pid)
		if err != nil {
			return nil, err
		}

		p.AppendAck(res.pid)
	}

	res.payload, err = ioutil.ReadAll(buf)
	if err != nil {
		return nil, err
	}

	return res, err
}

func IsControlPacket(t PacketType) bool {
	switch t {
	case 0:
		return false
	case P_DATA_V1, P_DATA_V2:
		return false
	}

	if t > 9 {
		return false
	}

	return true
}

func (pkt *ControlPacket) Bytes(ack []uint32) []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(byte(pkt.t)<<P_OPCODE_SHIFT | pkt.kid)
	buf.Write(pkt.sid[:])

	ack_cnt := byte(len(ack))
	buf.WriteByte(ack_cnt)

	if ack_cnt > 0 {
		for _, i := range ack {
			//log.Printf("[debug] Including in packet ACK for %d", i)
			binary.Write(buf, binary.BigEndian, i)
		}

		buf.Write(pkt.RemoteId[:])
	}
	if pkt.hasPid {
		binary.Write(buf, binary.BigEndian, pkt.pid)
	}
	buf.Write(pkt.payload)
	return buf.Bytes()
}

func (pkt *ControlPacket) SetPid(pid uint32) {
	pkt.hasPid = true
	pkt.pid = pid
}
