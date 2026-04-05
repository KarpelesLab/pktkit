package ovpn

import (
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
)

// AdapterConfig configures an OpenVPN [Adapter].
type AdapterConfig struct {
	// TLSConfig is the TLS configuration for the OpenVPN server.
	// Must include at least one certificate.
	TLSConfig *tls.Config

	// ListenAddr is the address to listen on (e.g. ":1194").
	// Both TCP and UDP listeners are started on this address.
	ListenAddr string

	// Connector wires each peer's L3Device to the network. Use a
	// [slirp.Stack] or [nat.NAT] for per-peer namespace-isolated NAT.
	// Exactly one of Connector or L2Connector must be set.
	Connector pktkit.L3Connector

	// L2Connector wires each peer as an L2Device on a shared network.
	// Use an [*pktkit.L2Hub] for a shared broadcast domain.
	// Exactly one of Connector or L2Connector must be set.
	L2Connector pktkit.L2Connector

	// Addr is the IP prefix for L2Connector mode (used by the L2Adapter
	// for ARP). Ignored in L3Connector mode.
	Addr netip.Prefix

	// OnAuth is called when a peer authenticates. It receives the
	// credentials and must return the IP configuration to push to the
	// client, or an error to reject the connection.
	OnAuth func(AuthInfo) (PeerConfig, error)
}

// AuthInfo contains the authentication credentials presented by an
// OpenVPN client during the TLS key exchange.
type AuthInfo struct {
	Username   string
	Password   string
	RemoteAddr net.Addr
	PeerInfo   map[string]string
	DevType    string // "tun" or "tap"
}

// PeerConfig is returned by the OnAuth callback and describes the
// IP configuration to push to the authenticated client.
type PeerConfig struct {
	// IP is the tunnel address to assign to the client.
	IP netip.Addr
	// Mask is the subnet mask (formatted as IP for OpenVPN's ifconfig).
	Mask net.IP
	// Gateway is the gateway address (used in tun/net30 topology).
	Gateway netip.Addr
	// PrefixLen is the prefix length for the L3Device's address.
	PrefixLen int
}

// Adapter bridges OpenVPN peers to pktkit networking. Each peer that
// completes a TLS handshake and authenticates gets a per-peer device
// connected to the configured connector.
//
// In tun mode with an [pktkit.L3Connector]: each peer gets a namespace-
// isolated L3Device. Decrypted IP packets flow directly between the
// OpenVPN tunnel and the network.
//
// In tap mode with an [pktkit.L2Connector]: each peer gets an L2Device
// on a shared broadcast domain. Decrypted Ethernet frames flow between
// the tunnel and the hub.
type Adapter struct {
	ovpn        *OVpn
	connector   pktkit.L3Connector
	l2connector pktkit.L2Connector
	addr        netip.Prefix
	onAuth      func(AuthInfo) (PeerConfig, error)

	mu    sync.RWMutex
	peers map[Addr]*ovpnPeer
}

type ovpnPeer struct {
	key     Addr
	dev     *peerL3Device
	l2dev   *peerL2Device
	l2a     *pktkit.L2Adapter
	cleanup func() error
}

// NewAdapter creates a new OpenVPN adapter with the given configuration.
func NewAdapter(cfg AdapterConfig) (*Adapter, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("ovpn: TLSConfig is required")
	}
	if cfg.ListenAddr == "" {
		return nil, errors.New("ovpn: ListenAddr is required")
	}
	if cfg.Connector == nil && cfg.L2Connector == nil {
		return nil, errors.New("ovpn: exactly one of Connector or L2Connector must be set")
	}
	if cfg.Connector != nil && cfg.L2Connector != nil {
		return nil, errors.New("ovpn: exactly one of Connector or L2Connector must be set")
	}
	if cfg.OnAuth == nil {
		return nil, errors.New("ovpn: OnAuth callback is required")
	}

	a := &Adapter{
		connector:   cfg.Connector,
		l2connector: cfg.L2Connector,
		addr:        cfg.Addr,
		onAuth:      cfg.OnAuth,
		peers:       make(map[Addr]*ovpnPeer),
	}

	ovpn, err := newOVpn(cfg.ListenAddr, cfg.TLSConfig)
	if err != nil {
		return nil, err
	}
	ovpn.adapter = a
	a.ovpn = ovpn

	return a, nil
}

// Close shuts down the adapter and all peer connections.
func (a *Adapter) Close() error {
	a.ovpn.Terminate()

	a.mu.Lock()
	peers := make(map[Addr]*ovpnPeer, len(a.peers))
	for k, v := range a.peers {
		peers[k] = v
	}
	a.peers = make(map[Addr]*ovpnPeer)
	a.mu.Unlock()

	for _, p := range peers {
		a.teardownPeerLocked(p)
	}
	return nil
}

// onPeerAuthenticated is called from peer-control.go when the TLS
// handshake and key exchange complete. It authenticates the peer,
// creates the appropriate device, and wires it to the connector.
func (a *Adapter) onPeerAuthenticated(p *Peer, username, password string, peerInfo map[string]string) (PeerConfig, error) {
	info := AuthInfo{
		Username: username,
		Password: password,
		PeerInfo: peerInfo,
		DevType:  p.opts.DevType,
	}

	peerCfg, err := a.onAuth(info)
	if err != nil {
		return PeerConfig{}, err
	}

	peer := &ovpnPeer{key: p.key}
	prefix := netip.PrefixFrom(peerCfg.IP, peerCfg.PrefixLen)

	switch p.opts.DevType {
	case "tun":
		dev := &peerL3Device{peer: p}
		dev.addr.Store(prefix)
		peer.dev = dev

		if a.connector != nil {
			cleanup, err := a.connector.ConnectL3(dev)
			if err != nil {
				return PeerConfig{}, err
			}
			peer.cleanup = cleanup
		} else {
			// tun + L2Connector: wrap in L2Adapter
			l2a := pktkit.NewL2Adapter(dev, nil)
			if a.addr.IsValid() {
				l2a.SetGateway(a.addr.Addr())
			}
			cleanup, err := a.l2connector.ConnectL2(l2a)
			if err != nil {
				l2a.Close()
				return PeerConfig{}, err
			}
			peer.l2a = l2a
			peer.cleanup = cleanup
		}

		p.onL3Packet = dev.deliver

	case "tap":
		if a.connector != nil {
			return PeerConfig{}, errors.New("ovpn: tap mode requires L2Connector, not L3Connector")
		}

		dev := &peerL2Device{peer: p}
		peer.l2dev = dev

		cleanup, err := a.l2connector.ConnectL2(dev)
		if err != nil {
			return PeerConfig{}, err
		}
		peer.cleanup = cleanup

		p.onL2Packet = dev.deliver

	default:
		return PeerConfig{}, errors.New("ovpn: unknown dev-type: " + p.opts.DevType)
	}

	a.mu.Lock()
	a.peers[p.key] = peer
	a.mu.Unlock()

	return peerCfg, nil
}

// onPeerDisconnected cleans up the network plumbing for a disconnected peer.
func (a *Adapter) onPeerDisconnected(key Addr) {
	a.mu.Lock()
	p, ok := a.peers[key]
	if ok {
		delete(a.peers, key)
	}
	a.mu.Unlock()

	if ok {
		a.teardownPeerLocked(p)
	}
}

func (a *Adapter) teardownPeerLocked(p *ovpnPeer) {
	if p.l2a != nil {
		p.l2a.Close()
	}
	if p.cleanup != nil {
		p.cleanup()
	}
}

// --- peerL3Device implements pktkit.L3Device for tun-mode peers ---

type peerL3Device struct {
	peer    *Peer
	handler atomic.Pointer[func(pktkit.Packet) error]
	addr    atomic.Value // netip.Prefix
}

func (d *peerL3Device) Send(pkt pktkit.Packet) error {
	return d.peer.SendData([]byte(pkt))
}

func (d *peerL3Device) SetHandler(h func(pktkit.Packet) error) {
	d.handler.Store(&h)
}

func (d *peerL3Device) deliver(pkt pktkit.Packet) {
	if h := d.handler.Load(); h != nil {
		(*h)(pkt)
	}
}

func (d *peerL3Device) Addr() netip.Prefix {
	if v, ok := d.addr.Load().(netip.Prefix); ok {
		return v
	}
	return netip.Prefix{}
}

func (d *peerL3Device) SetAddr(p netip.Prefix) error {
	d.addr.Store(p)
	return nil
}

func (d *peerL3Device) Close() error {
	return nil
}

// --- peerL2Device implements pktkit.L2Device for tap-mode peers ---

type peerL2Device struct {
	peer    *Peer
	handler atomic.Pointer[func(pktkit.Frame) error]
	mac     net.HardwareAddr
}

func (d *peerL2Device) Send(f pktkit.Frame) error {
	return d.peer.SendData([]byte(f))
}

func (d *peerL2Device) SetHandler(h func(pktkit.Frame) error) {
	d.handler.Store(&h)
}

func (d *peerL2Device) deliver(f pktkit.Frame) {
	if h := d.handler.Load(); h != nil {
		(*h)(f)
	}
}

func (d *peerL2Device) HWAddr() net.HardwareAddr {
	return d.mac
}

func (d *peerL2Device) Close() error {
	return nil
}
