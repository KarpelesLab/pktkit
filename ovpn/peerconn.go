package ovpn

import (
	"errors"
	"io"
	"net"
	"time"
)

// PeerConn satisfies net.Conn for use of openssl

type PeerConn struct {
	p *Peer

	readBuf  []byte
	readChan chan []byte
	closed   bool
}

func MakePeerConn(p *Peer) *PeerConn {
	res := &PeerConn{
		p:        p,
		readChan: make(chan []byte),
	}
	return res
}

func (pc *PeerConn) Read(b []byte) (n int, err error) {
	maxRead := len(b)
	localBuf := len(pc.readBuf)

	for localBuf == 0 {
		var rcvd bool
		pc.readBuf, rcvd = <-pc.readChan
		if !rcvd {
			// closed chan
			return 0, io.EOF
		}
		localBuf = len(pc.readBuf)
	}

	// local buffer fits in b ?
	if maxRead >= localBuf {
		copy(b, pc.readBuf)
		pc.readBuf = []byte{}
		return localBuf, nil
	}

	n = copy(b, pc.readBuf)
	pc.readBuf = pc.readBuf[n:]

	return n, nil
}

func (pc *PeerConn) Write(b []byte) (n int, err error) {
	n = len(b)
	if n == 0 {
		return 0, nil
	}

	if n > CONTROL_CHANNEL_MTU {
		final_n := int(0)
		for i := 0; i < n; i += CONTROL_CHANNEL_MTU {
			end := i + CONTROL_CHANNEL_MTU
			if end > n {
				end = n
			}
			xn, err := pc.Write(b[i:end])
			final_n += xn
			if err != nil {
				return xn, err
			}
		}
		return final_n, nil
	}

	pkt := MakeControlPacket(pc.p, P_CONTROL_V1, 0)
	pkt.payload = make([]byte, n)
	copy(pkt.payload, b)

	return n, pc.p.SendPacket(pkt)
}

func (pc *PeerConn) Close() error {
	pc.p.Close()
	return nil
}

func (pc *PeerConn) LocalAddr() net.Addr {
	// todo return our local addr, not the remote addr
	return pc.p.Key().TCPAddr()
}

func (pc *PeerConn) RemoteAddr() net.Addr {
	return pc.p.Key().TCPAddr()
}

func (pc *PeerConn) SetDeadline(t time.Time) error {
	return errors.New("SetDeadLine not supported on PeerConn")
}

func (pc *PeerConn) SetReadDeadline(t time.Time) error {
	return errors.New("SetReadDeadLine not supported on PeerConn")
}

func (pc *PeerConn) SetWriteDeadline(t time.Time) error {
	return errors.New("SetWriteDeadline not supported on PeerConn")
}
