package vclient

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/pktkit/slirp"
)

// errTimeout is returned when a read deadline expires.
var errTimeout = &timeoutError{}

type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// UDPConn is a virtual UDP connection implementing net.Conn.
type UDPConn struct {
	localIP    [4]byte
	localPort  uint16
	remoteIP   [4]byte
	remotePort uint16

	c *Client

	recvMu        sync.Mutex
	recvBuf       [][]byte // queue of received datagrams
	recvCond      *sync.Cond
	closedForRead bool // protected by recvMu

	closed       atomic.Bool  // for non-blocking checks in Write
	readDeadline atomic.Value // stores time.Time
}

func newUDPConn(c *Client, localIP [4]byte, localPort uint16, remoteIP [4]byte, remotePort uint16) *UDPConn {
	u := &UDPConn{
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		c:          c,
	}
	u.recvCond = sync.NewCond(&u.recvMu)
	return u
}

func (u *UDPConn) Read(b []byte) (int, error) {
	u.recvMu.Lock()
	defer u.recvMu.Unlock()

	for len(u.recvBuf) == 0 {
		if u.closedForRead {
			return 0, errors.New("connection closed")
		}

		// Check read deadline
		var dl time.Time
		if v := u.readDeadline.Load(); v != nil {
			dl = v.(time.Time)
		}
		if !dl.IsZero() {
			if time.Now().After(dl) {
				return 0, errTimeout
			}
			// Set up a timer to wake us when the deadline expires
			timer := time.AfterFunc(time.Until(dl), func() {
				u.recvCond.Broadcast()
			})
			u.recvCond.Wait()
			timer.Stop()
		} else {
			u.recvCond.Wait()
		}
	}

	pkt := u.recvBuf[0]
	u.recvBuf = u.recvBuf[1:]
	n := copy(b, pkt)
	return n, nil
}

func (u *UDPConn) Write(b []byte) (int, error) {
	if u.closed.Load() {
		return 0, errors.New("connection closed")
	}
	return u.writePacket(b)
}

func (u *UDPConn) writePacket(payload []byte) (int, error) {
	// Build IP + UDP headers
	ipHdr := make([]byte, 20)
	udpHdr := make([]byte, 8)
	totalLen := 20 + 8 + len(payload)

	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[8] = 64
	ipHdr[9] = 17 // UDP
	copy(ipHdr[12:16], u.localIP[:])
	copy(ipHdr[16:20], u.remoteIP[:])
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], slirp.IPChecksum(ipHdr))

	binary.BigEndian.PutUint16(udpHdr[0:2], u.localPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], u.remotePort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(udpHdr[6:8], 0)
	binary.BigEndian.PutUint16(udpHdr[6:8], slirp.UDPChecksum(ipHdr[12:16], ipHdr[16:20], udpHdr, payload))

	pkt := make([]byte, len(ipHdr)+len(udpHdr)+len(payload))
	copy(pkt, ipHdr)
	copy(pkt[len(ipHdr):], udpHdr)
	copy(pkt[len(ipHdr)+len(udpHdr):], payload)

	if err := u.c.sendPacket(pkt); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (u *UDPConn) Close() error {
	if !u.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal readers under the recvMu lock to avoid the race
	u.recvMu.Lock()
	u.closedForRead = true
	u.recvCond.Broadcast()
	u.recvMu.Unlock()

	u.c.udpMu.Lock()
	delete(u.c.udpConns, connKey{
		localPort:  u.localPort,
		remoteIP:   u.remoteIP,
		remotePort: u.remotePort,
	})
	u.c.udpMu.Unlock()
	return nil
}

func (u *UDPConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(u.localIP[:]).To4(), Port: int(u.localPort)}
}

func (u *UDPConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(u.remoteIP[:]).To4(), Port: int(u.remotePort)}
}

func (u *UDPConn) SetDeadline(t time.Time) error {
	u.SetReadDeadline(t)
	u.SetWriteDeadline(t)
	return nil
}

func (u *UDPConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Store(t)
	u.recvCond.Broadcast()
	return nil
}

func (u *UDPConn) SetWriteDeadline(t time.Time) error { return nil }

// handleInbound delivers an incoming datagram to this connection.
func (u *UDPConn) handleInbound(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)

	u.recvMu.Lock()
	u.recvBuf = append(u.recvBuf, data)
	u.recvMu.Unlock()
	u.recvCond.Broadcast()
}

// UDPConn6 is a virtual IPv6 UDP connection implementing net.Conn.
type UDPConn6 struct {
	localIP    [16]byte
	localPort  uint16
	remoteIP   [16]byte
	remotePort uint16

	c *Client

	recvMu        sync.Mutex
	recvBuf       [][]byte // queue of received datagrams
	recvCond      *sync.Cond
	closedForRead bool // protected by recvMu

	closed       atomic.Bool  // for non-blocking checks in Write
	readDeadline atomic.Value // stores time.Time
}

func newUDPConn6(c *Client, localIP [16]byte, localPort uint16, remoteIP [16]byte, remotePort uint16) *UDPConn6 {
	u := &UDPConn6{
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		c:          c,
	}
	u.recvCond = sync.NewCond(&u.recvMu)
	return u
}

func (u *UDPConn6) Read(b []byte) (int, error) {
	u.recvMu.Lock()
	defer u.recvMu.Unlock()

	for len(u.recvBuf) == 0 {
		if u.closedForRead {
			return 0, errors.New("connection closed")
		}

		// Check read deadline
		var dl time.Time
		if v := u.readDeadline.Load(); v != nil {
			dl = v.(time.Time)
		}
		if !dl.IsZero() {
			if time.Now().After(dl) {
				return 0, errTimeout
			}
			timer := time.AfterFunc(time.Until(dl), func() {
				u.recvCond.Broadcast()
			})
			u.recvCond.Wait()
			timer.Stop()
		} else {
			u.recvCond.Wait()
		}
	}

	pkt := u.recvBuf[0]
	u.recvBuf = u.recvBuf[1:]
	n := copy(b, pkt)
	return n, nil
}

func (u *UDPConn6) Write(b []byte) (int, error) {
	if u.closed.Load() {
		return 0, errors.New("connection closed")
	}
	return u.writePacket(b)
}

func (u *UDPConn6) writePacket(payload []byte) (int, error) {
	// Build IPv6 + UDP headers
	ipHdr := make([]byte, 40)
	udpHdr := make([]byte, 8)
	udpLen := 8 + len(payload)

	ipHdr[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(udpLen))
	ipHdr[6] = 17 // Next Header: UDP
	ipHdr[7] = 64 // Hop Limit
	copy(ipHdr[8:24], u.localIP[:])
	copy(ipHdr[24:40], u.remoteIP[:])

	binary.BigEndian.PutUint16(udpHdr[0:2], u.localPort)
	binary.BigEndian.PutUint16(udpHdr[2:4], u.remotePort)
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpHdr[6:8], 0)

	// Compute UDP checksum with IPv6 pseudo-header
	checksumData := make([]byte, len(udpHdr)+len(payload))
	copy(checksumData, udpHdr)
	copy(checksumData[len(udpHdr):], payload)
	cs := slirp.IPv6Checksum(u.localIP, u.remoteIP, 17, uint32(udpLen), checksumData)
	binary.BigEndian.PutUint16(udpHdr[6:8], cs)

	pkt := make([]byte, 40+len(udpHdr)+len(payload))
	copy(pkt, ipHdr)
	copy(pkt[40:], udpHdr)
	copy(pkt[40+len(udpHdr):], payload)

	if err := u.c.sendPacket(pkt); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (u *UDPConn6) Close() error {
	if !u.closed.CompareAndSwap(false, true) {
		return nil
	}

	u.recvMu.Lock()
	u.closedForRead = true
	u.recvCond.Broadcast()
	u.recvMu.Unlock()

	u.c.udpMu.Lock()
	delete(u.c.udpConns6, connKey6{
		localPort:  u.localPort,
		remoteIP:   u.remoteIP,
		remotePort: u.remotePort,
	})
	u.c.udpMu.Unlock()
	return nil
}

func (u *UDPConn6) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(u.localIP[:]), Port: int(u.localPort)}
}

func (u *UDPConn6) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP(u.remoteIP[:]), Port: int(u.remotePort)}
}

func (u *UDPConn6) SetDeadline(t time.Time) error {
	u.SetReadDeadline(t)
	u.SetWriteDeadline(t)
	return nil
}

func (u *UDPConn6) SetReadDeadline(t time.Time) error {
	u.readDeadline.Store(t)
	u.recvCond.Broadcast()
	return nil
}

func (u *UDPConn6) SetWriteDeadline(t time.Time) error { return nil }

// handleInbound delivers an incoming datagram to this IPv6 connection.
func (u *UDPConn6) handleInbound(payload []byte) {
	data := make([]byte, len(payload))
	copy(data, payload)

	u.recvMu.Lock()
	u.recvBuf = append(u.recvBuf, data)
	u.recvMu.Unlock()
	u.recvCond.Broadcast()
}

// handleUDP6 dispatches incoming IPv6 UDP datagrams to the appropriate connection.
func (c *Client) handleUDP6(ip []byte) error {
	udp := ip[40:]
	if len(udp) < 8 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	// Validate UDP length field
	udpLen := binary.BigEndian.Uint16(udp[4:6])
	if udpLen < 8 || int(udpLen) > len(udp) {
		return nil
	}
	payload := udp[8:udpLen]

	k := connKey6{localPort: dstPort, remoteIP: [16]byte(ip[8:24]), remotePort: srcPort}
	c.udpMu.Lock()
	conn := c.udpConns6[k]
	c.udpMu.Unlock()

	if conn != nil {
		conn.handleInbound(payload)
	}
	return nil
}

// handleUDP dispatches incoming UDP datagrams to the appropriate connection.
func (c *Client) handleUDP(ip []byte, ihl int) error {
	udp := ip[ihl:]
	if len(udp) < 8 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	// Validate UDP length field
	udpLen := binary.BigEndian.Uint16(udp[4:6])
	if udpLen < 8 || int(udpLen) > len(udp) {
		return nil
	}
	payload := udp[8:udpLen]

	k := connKey{localPort: dstPort, remoteIP: [4]byte(ip[12:16]), remotePort: srcPort}
	c.udpMu.Lock()
	conn := c.udpConns[k]
	c.udpMu.Unlock()

	if conn != nil {
		conn.handleInbound(payload)
	}
	return nil
}
