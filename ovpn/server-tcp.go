package ovpn

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type ServerTcp struct {
	o      *OVpn
	c      *net.TCPConn
	peer   *Peer
	wrLock sync.Mutex
}

func (o *OVpn) tcpThread() {
	o.termWait.Add(1)
	defer o.termWait.Done()

	for {
		c, err := o.tcp.AcceptTCP()
		if err != nil {
			if o.terminating.Load() {
				return
			}
			log.Println("[ovpn] Failed accepting TCP connection:", err)
			return
		}

		log.Println("[ovpn] TCP connection accepted from", c.RemoteAddr().String())

		err = o.ServerTcpClient(c)
		if err != nil {
			log.Println("[ovpn] Failed to spawn TCP client:", err)
		}
	}
}

func (o *OVpn) ServerTcpClient(c *net.TCPConn) error {
	k, err := addrKey(c.RemoteAddr())
	if err != nil {
		return err
	}
	res := &ServerTcp{o: o, c: c}

	o.peersLock.Lock()
	o.peers[k] = NewPeer(res, o, k)
	o.peersLock.Unlock()

	go res.TcpThread()
	return nil
}

func (c *ServerTcp) TcpThread() {
	c.c.SetKeepAlivePeriod(30 * time.Second)
	c.c.SetKeepAlive(true)
	c.c.SetNoDelay(true) // make sure packets are pushed through tcp stream quick
	b := bufio.NewReader(c.c)

	c.o.termWait.Add(1)
	defer c.o.termWait.Done()

	defer func() {
		if c.peer != nil {
			c.peer.Unregister()
		}
	}()

	for {
		var len uint16
		err := binary.Read(b, binary.BigEndian, &len)
		if err != nil {
			log.Printf("[ovpn] Failed to read from TCP peer: %v", err)
			c.c.Close()
			return
		}

		buf := make([]byte, len)
		_, err = io.ReadFull(b, buf)
		if err != nil {
			log.Printf("[ovpn] Failed to read from TCP peer: %v", err)
			c.c.Close()
			return
		}

		c.peer.handlePacket(buf)
	}
}

func (c *ServerTcp) Send(pkt []byte) error {
	c.wrLock.Lock()
	defer c.wrLock.Unlock()

	err := binary.Write(c.c, binary.BigEndian, uint16(len(pkt)))
	if err != nil {
		return err
	}
	_, err = c.c.Write(pkt)
	return err
}

func (c *ServerTcp) SetPeer(p *Peer) {
	c.peer = p
}

func (c *ServerTcp) Close() {
	c.c.Close()
}
