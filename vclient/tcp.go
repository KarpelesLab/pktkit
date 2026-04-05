package vclient

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vtcp"
)

// TCPConn is a virtual TCP connection implementing net.Conn.
// It wraps a vtcp.Conn and handles registration/unregistration
// with the parent Client.
type TCPConn struct {
	vc *vtcp.Conn
	c  *Client
	k  connKey
	k6 connKey6
	v6 bool // true when this connection uses IPv6
}

func (tc *TCPConn) Read(b []byte) (int, error)  { return tc.vc.Read(b) }
func (tc *TCPConn) Write(b []byte) (int, error) { return tc.vc.Write(b) }

func (tc *TCPConn) Close() error {
	err := tc.vc.Close()
	tc.c.tcpMu.Lock()
	if tc.v6 {
		delete(tc.c.tcpConns6, tc.k6)
	} else {
		delete(tc.c.tcpConns, tc.k)
	}
	tc.c.tcpMu.Unlock()
	return err
}

func (tc *TCPConn) LocalAddr() net.Addr                { return tc.vc.LocalAddr() }
func (tc *TCPConn) RemoteAddr() net.Addr               { return tc.vc.RemoteAddr() }
func (tc *TCPConn) SetDeadline(t time.Time) error      { return tc.vc.SetDeadline(t) }
func (tc *TCPConn) SetReadDeadline(t time.Time) error  { return tc.vc.SetReadDeadline(t) }
func (tc *TCPConn) SetWriteDeadline(t time.Time) error { return tc.vc.SetWriteDeadline(t) }

func (tc *TCPConn) abort() {
	tc.vc.Flush(tc.vc.Abort())
}

// handleTCP dispatches incoming TCP segments to the appropriate connection.
func (c *Client) handleTCP(ip []byte, ihl int) error {
	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	var srcIP, dstIP [4]byte
	copy(srcIP[:], ip[12:16])
	copy(dstIP[:], ip[16:20])

	k := connKey{localPort: dstPort, remoteIP: srcIP, remotePort: srcPort}
	c.tcpMu.Lock()
	conn := c.tcpConns[k]
	c.tcpMu.Unlock()

	if conn != nil {
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			return nil
		}
		conn.vc.Flush(conn.vc.HandleSegment(seg))
		return nil
	}

	// No existing connection — check flags.
	flags := tcp[13]

	// Non-SYN: try SYN cookie validation before dropping.
	if flags&(vtcp.FlagSYN|vtcp.FlagACK) != vtcp.FlagSYN {
		if (flags & vtcp.FlagACK) != 0 {
			c.listenerMu.Lock()
			l := c.listeners[dstPort]
			c.listenerMu.Unlock()
			if l != nil {
				seg, err := vtcp.ParseSegment(tcp)
				if err == nil {
					if mss, _, ok := c.syncookies.ValidateACK(seg, dstPort); ok {
						return c.acceptCookieConn4(seg, k, dstIP, srcIP, dstPort, srcPort, mss, l)
					}
				}
			}
		}
		return nil
	}

	c.listenerMu.Lock()
	l := c.listeners[dstPort]
	c.listenerMu.Unlock()
	if l == nil {
		return nil // no listener on this port
	}

	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		return nil
	}

	// If the accept queue is nearly full, use SYN cookies.
	if len(l.acceptCh) >= cap(l.acceptCh)-1 {
		synack := c.syncookies.GenerateSYNACK(seg, dstPort, 1460)
		pkt := buildIPv4Packet(dstIP, srcIP, synack.Marshal())
		return c.sendPacket(pkt)
	}

	// Normal path: create a vtcp.Conn.
	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv4Packet(dstIP, srcIP, tcpSeg))
		},
		MSS:       1460,
		Keepalive: true,
	})

	tc := &TCPConn{vc: vc, c: c, k: k}

	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	vc.Flush(vc.AcceptSYN(seg))

	// Queue for Accept() only after the three-way handshake completes.
	// The ACK may be queued by the trampoline (flushing flag) rather than
	// sent immediately, so the connection might still be in SYN-RECEIVED.
	go func() {
		select {
		case <-vc.Established():
			select {
			case l.acceptCh <- tc:
			case <-l.closeCh:
				tc.vc.Flush(tc.vc.Abort())
				c.tcpMu.Lock()
				delete(c.tcpConns, k)
				c.tcpMu.Unlock()
			}
		case <-l.closeCh:
			tc.vc.Flush(tc.vc.Abort())
			c.tcpMu.Lock()
			delete(c.tcpConns, k)
			c.tcpMu.Unlock()
		}
	}()

	return nil
}

// handleTCP6 dispatches incoming IPv6 TCP segments to the appropriate connection.
func (c *Client) handleTCP6(ip []byte) error {
	tcp := ip[40:]
	if len(tcp) < 20 {
		return nil
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	var srcIP, dstIP [16]byte
	copy(srcIP[:], ip[8:24])
	copy(dstIP[:], ip[24:40])

	k := connKey6{localPort: dstPort, remoteIP: srcIP, remotePort: srcPort}
	c.tcpMu.Lock()
	conn := c.tcpConns6[k]
	c.tcpMu.Unlock()

	if conn != nil {
		seg, err := vtcp.ParseSegment(tcp)
		if err != nil {
			return nil
		}
		conn.vc.Flush(conn.vc.HandleSegment(seg))
		return nil
	}

	// No existing connection — check flags.
	flags := tcp[13]

	// Non-SYN: try SYN cookie validation before dropping.
	if flags&(vtcp.FlagSYN|vtcp.FlagACK) != vtcp.FlagSYN {
		if (flags & vtcp.FlagACK) != 0 {
			c.listenerMu.Lock()
			l := c.listeners[dstPort]
			c.listenerMu.Unlock()
			if l != nil {
				seg, err := vtcp.ParseSegment(tcp)
				if err == nil {
					if mss, _, ok := c.syncookies.ValidateACK(seg, dstPort); ok {
						return c.acceptCookieConn6(seg, k, dstIP, srcIP, dstPort, srcPort, mss, l)
					}
				}
			}
		}
		return nil
	}

	c.listenerMu.Lock()
	l := c.listeners[dstPort]
	c.listenerMu.Unlock()
	if l == nil {
		return nil
	}

	seg, err := vtcp.ParseSegment(tcp)
	if err != nil {
		return nil
	}

	// If the accept queue is nearly full, use SYN cookies.
	if len(l.acceptCh) >= cap(l.acceptCh)-1 {
		synack := c.syncookies.GenerateSYNACK(seg, dstPort, 1440)
		pkt := buildIPv6Packet(dstIP, srcIP, synack.Marshal())
		return c.sendPacket(pkt)
	}

	// Normal path: create a vtcp.Conn.
	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv6Packet(dstIP, srcIP, tcpSeg))
		},
		MSS:       1440,
		Keepalive: true,
	})

	tc := &TCPConn{vc: vc, c: c, k6: k, v6: true}

	c.tcpMu.Lock()
	c.tcpConns6[k] = tc
	c.tcpMu.Unlock()

	vc.Flush(vc.AcceptSYN(seg))

	// Queue for Accept() only after the three-way handshake completes.
	go func() {
		select {
		case <-vc.Established():
			select {
			case l.acceptCh <- tc:
			case <-l.closeCh:
				tc.vc.Flush(tc.vc.Abort())
				c.tcpMu.Lock()
				delete(c.tcpConns6, k)
				c.tcpMu.Unlock()
			}
		case <-l.closeCh:
			tc.vc.Flush(tc.vc.Abort())
			c.tcpMu.Lock()
			delete(c.tcpConns6, k)
			c.tcpMu.Unlock()
		}
	}()

	return nil
}

// buildIPv4Packet builds an IPv4 packet containing a raw TCP segment.
func buildIPv4Packet(srcIP, dstIP [4]byte, tcpSeg []byte) []byte {
	ipHdr := make([]byte, 20)
	totalLen := 20 + len(tcpSeg)
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(totalLen))
	ipHdr[8] = 64
	ipHdr[9] = 6 // TCP
	copy(ipHdr[12:16], srcIP[:])
	copy(ipHdr[16:20], dstIP[:])
	binary.BigEndian.PutUint16(ipHdr[10:12], 0)
	binary.BigEndian.PutUint16(ipHdr[10:12], slirp.IPChecksum(ipHdr))

	// Compute TCP checksum
	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	if len(tcpCopy) >= 18 {
		binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
		doff := int(tcpCopy[12]>>4) * 4
		if doff > 0 && doff <= len(tcpCopy) {
			hdr := tcpCopy[:doff]
			payload := tcpCopy[doff:]
			cs := slirp.TCPChecksum(ipHdr[12:16], ipHdr[16:20], hdr, payload)
			binary.BigEndian.PutUint16(tcpCopy[16:18], cs)
		}
	}

	pkt := make([]byte, len(ipHdr)+len(tcpCopy))
	copy(pkt, ipHdr)
	copy(pkt[len(ipHdr):], tcpCopy)
	return pkt
}

// buildIPv6Packet builds an IPv6 packet containing a raw TCP segment.
func buildIPv6Packet(srcIP, dstIP [16]byte, tcpSeg []byte) []byte {
	ipHdr := make([]byte, 40)
	ipHdr[0] = 0x60 // Version 6
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(len(tcpSeg)))
	ipHdr[6] = 6  // Next Header: TCP
	ipHdr[7] = 64 // Hop Limit
	copy(ipHdr[8:24], srcIP[:])
	copy(ipHdr[24:40], dstIP[:])

	// Compute TCP checksum with IPv6 pseudo-header
	tcpCopy := make([]byte, len(tcpSeg))
	copy(tcpCopy, tcpSeg)
	if len(tcpCopy) >= 18 {
		binary.BigEndian.PutUint16(tcpCopy[16:18], 0)
		cs := slirp.IPv6Checksum(srcIP, dstIP, 6, uint32(len(tcpCopy)), tcpCopy)
		binary.BigEndian.PutUint16(tcpCopy[16:18], cs)
	}

	pkt := make([]byte, 40+len(tcpCopy))
	copy(pkt, ipHdr)
	copy(pkt[40:], tcpCopy)
	return pkt
}

// acceptCookieConn4 creates a connection from a validated SYN cookie (IPv4).
func (c *Client) acceptCookieConn4(seg vtcp.Segment, k connKey, dstIP, srcIP [4]byte, dstPort, srcPort, mss uint16, l *Listener) error {
	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]).To4(), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]).To4(), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv4Packet(dstIP, srcIP, tcpSeg))
		},
		MSS:       int(mss),
		Keepalive: true,
	})

	tc := &TCPConn{vc: vc, c: c, k: k}

	c.tcpMu.Lock()
	c.tcpConns[k] = tc
	c.tcpMu.Unlock()

	vc.Flush(vc.AcceptCookie(seg.Seq, seg.Ack-1, mss, seg.Payload))

	select {
	case l.acceptCh <- tc:
	case <-l.closeCh:
		tc.vc.Flush(tc.vc.Abort())
		c.tcpMu.Lock()
		delete(c.tcpConns, k)
		c.tcpMu.Unlock()
	default:
		tc.vc.Flush(tc.vc.Abort())
		c.tcpMu.Lock()
		delete(c.tcpConns, k)
		c.tcpMu.Unlock()
	}
	return nil
}

// acceptCookieConn6 creates a connection from a validated SYN cookie (IPv6).
func (c *Client) acceptCookieConn6(seg vtcp.Segment, k connKey6, dstIP, srcIP [16]byte, dstPort, srcPort, mss uint16, l *Listener) error {
	localAddr := &net.TCPAddr{IP: net.IP(dstIP[:]), Port: int(dstPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(srcIP[:]), Port: int(srcPort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  dstPort,
		RemotePort: srcPort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv6Packet(dstIP, srcIP, tcpSeg))
		},
		MSS:       int(mss),
		Keepalive: true,
	})

	tc := &TCPConn{vc: vc, c: c, k6: k, v6: true}

	c.tcpMu.Lock()
	c.tcpConns6[k] = tc
	c.tcpMu.Unlock()

	vc.Flush(vc.AcceptCookie(seg.Seq, seg.Ack-1, mss, seg.Payload))

	select {
	case l.acceptCh <- tc:
	case <-l.closeCh:
		tc.vc.Flush(tc.vc.Abort())
		c.tcpMu.Lock()
		delete(c.tcpConns6, k)
		c.tcpMu.Unlock()
	default:
		tc.vc.Flush(tc.vc.Abort())
		c.tcpMu.Lock()
		delete(c.tcpConns6, k)
		c.tcpMu.Unlock()
	}
	return nil
}
