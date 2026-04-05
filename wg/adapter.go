package wg

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
)

// AdapterConfig configures a WireGuard [Adapter].
type AdapterConfig struct {
	// PrivateKey is the local WireGuard identity. If zero, a new key is generated.
	PrivateKey NoisePrivateKey

	// Connector wires each peer's L3Device to the network. Use a
	// [slirp.Stack] or [nat.NAT] for per-peer namespace-isolated NAT.
	// Exactly one of Connector or L2Connector must be set.
	Connector pktkit.L3Connector

	// L2Connector wires each peer as an L2Device on a shared network.
	// Use an [*pktkit.L2Hub] for a shared broadcast domain. When set,
	// Addr must also be set for ARP resolution. Exactly one of
	// Connector or L2Connector must be set.
	L2Connector pktkit.L2Connector

	// Addr is the IP prefix for the peer's L3Device. Required for
	// L2Connector mode (used by the L2Adapter for ARP). Ignored in
	// L3Connector mode.
	Addr netip.Prefix

	// OnUnknownPeer is called when an unauthorized peer initiates a handshake.
	// Call [Adapter.AddPeer] from this callback (or later) to authorize it,
	// then call [Adapter.AcceptUnknownPeer] to complete the handshake.
	OnUnknownPeer func(key NoisePublicKey, addr *net.UDPAddr, packet []byte)
}

// Adapter bridges WireGuard peers to pktkit networking. Each peer that
// completes a handshake gets a per-peer L3Device connected to the
// configured connector.
//
// With an [pktkit.L3Connector] (e.g. [slirp.Stack]): each peer gets
// a namespace-isolated NAT connection. Decrypted IP packets flow directly
// between the WireGuard tunnel and the NAT engine — no L2 framing overhead.
//
// With an [pktkit.L2Connector] (e.g. [*pktkit.L2Hub]): each peer's
// L3Device is wrapped in an L2Adapter for Ethernet framing on a shared
// broadcast domain.
type Adapter struct {
	handler     *Handler
	server      *Server
	connector   pktkit.L3Connector
	l2connector pktkit.L2Connector
	addr        netip.Prefix

	mu    sync.RWMutex
	peers map[NoisePublicKey]*wgPeer
}

// wgPeer tracks one connected WireGuard peer's network plumbing.
type wgPeer struct {
	key     NoisePublicKey
	dev     *peerL3Device
	l2a     *pktkit.L2Adapter // non-nil only in L2 mode
	cleanup func() error
}

// peerL3Device is an L3Device representing one WireGuard peer on the
// server side. It separates the two data directions:
//
//   - Send: called by the network (Stack or L2Adapter) to deliver a packet
//     TO this peer → encrypts and sends via WireGuard.
//   - handler: called when a packet arrives FROM this peer (decrypted) →
//     delivers to the network (Stack or L2Adapter).
type peerL3Device struct {
	adapter *Adapter
	key     NoisePublicKey
	handler atomic.Pointer[func(pktkit.Packet) error]
	addr    atomic.Value // netip.Prefix
}

// Send delivers a packet to this peer: encrypt and send via WireGuard.
func (d *peerL3Device) Send(pkt pktkit.Packet) error {
	return d.adapter.server.Send(pkt, d.key)
}

// SetHandler sets the callback for packets arriving from this peer.
func (d *peerL3Device) SetHandler(h func(pktkit.Packet) error) {
	d.handler.Store(&h)
}

// deliver forwards a decrypted packet from the peer to the network.
func (d *peerL3Device) deliver(pkt pktkit.Packet) {
	if h := d.handler.Load(); h != nil {
		(*h)(pkt)
	}
}

func (d *peerL3Device) Addr() netip.Prefix {
	if v := d.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (d *peerL3Device) SetAddr(p netip.Prefix) error {
	d.addr.Store(p)
	return nil
}

func (d *peerL3Device) Close() error { return nil }

// NewAdapter creates a WireGuard adapter. Call [Adapter.Serve] to start.
func NewAdapter(cfg AdapterConfig) (*Adapter, error) {
	if cfg.Connector == nil && cfg.L2Connector == nil {
		return nil, fmt.Errorf("wg: either Connector or L2Connector is required")
	}
	if cfg.Connector != nil && cfg.L2Connector != nil {
		return nil, fmt.Errorf("wg: Connector and L2Connector are mutually exclusive")
	}

	h, err := NewHandler(Config{
		PrivateKey:    cfg.PrivateKey,
		OnUnknownPeer: cfg.OnUnknownPeer,
	})
	if err != nil {
		return nil, err
	}

	a := &Adapter{
		handler:     h,
		connector:   cfg.Connector,
		l2connector: cfg.L2Connector,
		addr:        cfg.Addr,
		peers:       make(map[NoisePublicKey]*wgPeer),
	}

	s, err := NewServer(ServerConfig{
		Handler: h,
		OnPacket: func(data []byte, peerKey NoisePublicKey, _ *Handler) {
			a.onPacket(data, peerKey)
		},
		OnPeerConnected: func(peerKey NoisePublicKey, _ *Handler) {
			a.onPeerConnected(peerKey)
		},
	})
	if err != nil {
		return nil, err
	}
	a.server = s

	return a, nil
}

// Serve starts the WireGuard read loop on conn. Blocks until [Close] is called.
func (a *Adapter) Serve(conn net.PacketConn) error {
	a.handler.SetConn(conn)
	return a.server.Serve(conn)
}

// AddPeer authorizes a peer by public key.
func (a *Adapter) AddPeer(key NoisePublicKey) {
	a.handler.AddPeer(key)
}

// AddPeerWithPSK authorizes a peer with a preshared key.
func (a *Adapter) AddPeerWithPSK(key NoisePublicKey, psk NoisePresharedKey) {
	a.handler.AddPeerWithPSK(key, psk)
}

// AcceptUnknownPeer authorizes a previously unknown peer and completes
// its handshake. The conn passed to [Serve] must be active.
func (a *Adapter) AcceptUnknownPeer(key NoisePublicKey, packet []byte, addr *net.UDPAddr) error {
	return a.handler.AcceptUnknownPeer(key, packet, addr)
}

// RemovePeer revokes a peer and tears down its network plumbing.
func (a *Adapter) RemovePeer(key NoisePublicKey) {
	a.handler.RemovePeer(key)
	a.teardownPeer(key)
}

// Connect initiates a handshake to a peer at the given address.
// The peer must be authorized first via [AddPeer].
func (a *Adapter) Connect(key NoisePublicKey, addr *net.UDPAddr) error {
	return a.server.Connect(key, addr)
}

// PublicKey returns the adapter's WireGuard public key.
func (a *Adapter) PublicKey() NoisePublicKey {
	return a.handler.PublicKey()
}

// Handler returns the underlying WireGuard protocol handler.
func (a *Adapter) Handler() *Handler {
	return a.handler
}

// Close stops the adapter and tears down all peer connections.
func (a *Adapter) Close() error {
	a.server.Close()

	a.mu.Lock()
	peers := a.peers
	a.peers = make(map[NoisePublicKey]*wgPeer)
	a.mu.Unlock()

	for _, p := range peers {
		if p.l2a != nil {
			p.l2a.Close()
		}
		if p.cleanup != nil {
			p.cleanup()
		}
	}

	return a.handler.Close()
}

// onPeerConnected is called by the Server when a handshake completes.
func (a *Adapter) onPeerConnected(key NoisePublicKey) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Already wired — nothing to do (rekey doesn't need new plumbing).
	if _, exists := a.peers[key]; exists {
		return
	}

	dev := &peerL3Device{adapter: a, key: key}
	dev.addr.Store(a.addr)

	peer := &wgPeer{key: key, dev: dev}

	if a.connector != nil {
		// L3 mode: wire directly to the Stack (no L2 framing).
		cleanup, err := a.connector.ConnectL3(dev)
		if err != nil {
			return
		}
		peer.cleanup = cleanup
	} else {
		// L2 mode: wrap in L2Adapter for Ethernet framing.
		l2a := pktkit.NewL2Adapter(dev, nil)
		cleanup, err := a.l2connector.ConnectL2(l2a)
		if err != nil {
			l2a.Close()
			return
		}
		peer.l2a = l2a
		peer.cleanup = cleanup
	}

	a.peers[key] = peer
}

// onPacket is called by the Server when a decrypted IP packet arrives.
func (a *Adapter) onPacket(data []byte, key NoisePublicKey) {
	a.mu.RLock()
	p := a.peers[key]
	a.mu.RUnlock()

	if p == nil {
		return
	}

	p.dev.deliver(pktkit.Packet(data))
}

// teardownPeer removes and cleans up a peer's network plumbing.
func (a *Adapter) teardownPeer(key NoisePublicKey) {
	a.mu.Lock()
	p, ok := a.peers[key]
	if ok {
		delete(a.peers, key)
	}
	a.mu.Unlock()

	if ok {
		if p.l2a != nil {
			p.l2a.Close()
		}
		if p.cleanup != nil {
			p.cleanup()
		}
	}
}
