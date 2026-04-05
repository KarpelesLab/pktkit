package ovpn

import (
	"log"
	"net"
)

type ServerUdp struct {
	o    *OVpn
	a    *net.UDPAddr
	peer *Peer
}

func (o *OVpn) udpThread() {
	o.termWait.Add(1)
	defer o.termWait.Done()

	buf := make([]byte, 65536)
	for {
		n, addr, err := o.udp.ReadFromUDP(buf)
		if err != nil {
			if o.terminating {
				return
			}
			log.Printf("[ovpn] Failed to read from udp: %v", err)
			return
		}
		//log.Printf("[ovpn] Received packet of %d bytes from %s", n, addr.String())

		// handle buf[:n]
		p, err := o.GetServerUdp(addr)
		if err != nil {
			log.Printf("[ovpn] Failed to instanciate UDP peer for packet from %v", addr.String())
			continue
		}
		p.handlePacket(buf[:n])
	}
}

func (o *OVpn) GetServerUdp(addr *net.UDPAddr) (*Peer, error) {
	k, err := addrKey(addr)
	if err != nil {
		return nil, err
	}

	o.peersLock.Lock()
	defer o.peersLock.Unlock()

	p, ok := o.peers[k]
	if ok {
		return p, nil
	}

	// need to create new
	sudp := &ServerUdp{o, addr, nil}
	peer := NewPeer(sudp, o, k)
	o.peers[k] = peer
	return peer, nil
}

func (c *ServerUdp) Send(buf []byte) error {
	_, err := c.o.udp.WriteToUDP(buf, c.a)
	return err
}

func (c *ServerUdp) SetPeer(p *Peer) {
	c.peer = p
}

func (c *ServerUdp) Close() {
	// nothing yet
}
