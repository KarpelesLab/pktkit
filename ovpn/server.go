package ovpn

import (
	"crypto/tls"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type OVpn struct {
	tcp     *net.TCPListener
	udp     *net.UDPConn
	threads int
	laddr   string

	termWait    sync.WaitGroup
	terminating atomic.Bool

	peersLock sync.Mutex
	peers     map[Addr]*Peer

	tlsConfig *tls.Config

	deathNote       chan *Peer
	heartBeat       *time.Ticker
	shutdownChannel chan struct{}

	adapter *Adapter
}

func newOVpn(laddr string, tlsCfg *tls.Config) (*OVpn, error) {
	tcpLaddr, err := net.ResolveTCPAddr("tcp", laddr)
	if err != nil {
		return nil, err
	}
	udpLaddr, err := net.ResolveUDPAddr("udp", laddr)
	if err != nil {
		return nil, err
	}

	res := &OVpn{
		threads:         runtime.NumCPU() * 2,
		laddr:           laddr,
		shutdownChannel: make(chan struct{}),
		peers:           make(map[Addr]*Peer),
		tlsConfig:       tlsCfg,
	}

	res.tcp, err = net.ListenTCP("tcp", tcpLaddr)
	if err != nil {
		return nil, err
	}
	res.udp, err = net.ListenUDP("udp", udpLaddr)
	if err != nil {
		res.terminating.Store(true)
		res.tcp.Close()
		return nil, err
	}

	go res.tcpThread()

	for i := 0; i < res.threads; i++ {
		go res.udpThread()
	}

	res.deathNote = make(chan *Peer)
	res.heartBeat = time.NewTicker(10 * time.Second)

	go res.reaper()
	go res.monitor()

	return res, nil
}

func (o *OVpn) Terminate() {
	o.terminating.Store(true)

	o.heartBeat.Stop()
	close(o.shutdownChannel)

	o.peersLock.Lock()
	for _, c := range o.peers {
		c.Close()
	}
	o.peersLock.Unlock()

	o.tcp.Close()
	o.udp.Close()
	o.termWait.Wait()
}

func (o *OVpn) monitor() {
	for {
		select {
		case <-o.shutdownChannel:
			close(o.deathNote)
			return
		case <-o.heartBeat.C:
			o.peersLock.Lock()
			for _, peer := range o.peers {
				if atomic.AddUint32(&peer.IdleTimer, 1) > 6 {
					o.deathNote <- peer
				}
			}
			o.peersLock.Unlock()
		}
	}
}

func (o *OVpn) reaper() {
	for peer := range o.deathNote {
		log.Printf("[ovpn] Reaping idle peer %v", peer)
		peer.Close()
	}
}
