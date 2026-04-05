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
	// Ignored if MultiHandler is set.
	PrivateKey NoisePrivateKey

	// MultiHandler provides multiple WireGuard identities on a single port.
	// When set, PrivateKey is ignored and the adapter operates in multi-key
	// mode. Use [Adapter.AddPeerTo] and [Adapter.RemovePeerFrom] to manage
	// peers per-identity, or [Adapter.AddPeer] to authorize on all identities.
	MultiHandler *MultiHandler

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
	handler      *Handler      // non-nil in single-key mode
	multiHandler *MultiHandler // non-nil in multi-key mode
	server       *Server
	connector    pktkit.L3Connector
	l2connector  pktkit.L2Connector
	addr         netip.Prefix

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

	a := &Adapter{
		connector:   cfg.Connector,
		l2connector: cfg.L2Connector,
		addr:        cfg.Addr,
		peers:       make(map[NoisePublicKey]*wgPeer),
	}

	serverCfg := ServerConfig{
		OnPacket: func(data []byte, peerKey NoisePublicKey, _ *Handler) {
			a.onPacket(data, peerKey)
		},
		OnPeerConnected: func(peerKey NoisePublicKey, _ *Handler) {
			a.onPeerConnected(peerKey)
		},
	}

	if cfg.MultiHandler != nil {
		a.multiHandler = cfg.MultiHandler
		serverCfg.MultiHandler = cfg.MultiHandler

		// Set OnUnknownPeer on all handlers if configured.
		if cfg.OnUnknownPeer != nil {
			for _, h := range cfg.MultiHandler.Handlers() {
				h.onUnknownPeer = cfg.OnUnknownPeer
			}
		}
	} else {
		h, err := NewHandler(Config{
			PrivateKey:    cfg.PrivateKey,
			OnUnknownPeer: cfg.OnUnknownPeer,
		})
		if err != nil {
			return nil, err
		}
		a.handler = h
		serverCfg.Handler = h
	}

	s, err := NewServer(serverCfg)
	if err != nil {
		return nil, err
	}
	a.server = s

	return a, nil
}

// Serve starts the WireGuard read loop on conn. Blocks until [Close] is called.
func (a *Adapter) Serve(conn net.PacketConn) error {
	if a.multiHandler != nil {
		for _, h := range a.multiHandler.Handlers() {
			h.SetConn(conn)
		}
	} else {
		a.handler.SetConn(conn)
	}
	return a.server.Serve(conn)
}

// AddPeer authorizes a peer by public key. In multi-key mode, the peer is
// authorized on all handlers. Use [AddPeerTo] to target a specific identity.
func (a *Adapter) AddPeer(key NoisePublicKey) {
	if a.multiHandler != nil {
		for _, h := range a.multiHandler.Handlers() {
			h.AddPeer(key)
		}
		return
	}
	a.handler.AddPeer(key)
}

// AddPeerTo authorizes a peer on a specific handler (multi-key mode).
func (a *Adapter) AddPeerTo(key NoisePublicKey, handler *Handler) {
	handler.AddPeer(key)
}

// AddPeerWithPSK authorizes a peer with a preshared key. In single-key mode
// only; use [AddPeerTo] with handler.AddPeerWithPSK in multi-key mode.
func (a *Adapter) AddPeerWithPSK(key NoisePublicKey, psk NoisePresharedKey) {
	a.handler.AddPeerWithPSK(key, psk)
}

// AcceptUnknownPeer authorizes a previously unknown peer and completes
// its handshake. In multi-key mode, the correct handler is determined
// automatically from the packet's MAC1.
func (a *Adapter) AcceptUnknownPeer(key NoisePublicKey, packet []byte, addr *net.UDPAddr) error {
	if a.multiHandler != nil {
		// Find which handler the packet is for via MAC1 check.
		for _, h := range a.multiHandler.Handlers() {
			if h.cookieChecker.CheckMAC1(packet) {
				return h.AcceptUnknownPeer(key, packet, addr)
			}
		}
		return fmt.Errorf("wg: no handler matched MAC1 for unknown peer")
	}
	return a.handler.AcceptUnknownPeer(key, packet, addr)
}

// RemovePeer revokes a peer and tears down its network plumbing.
// In multi-key mode, the peer is removed from all handlers.
func (a *Adapter) RemovePeer(key NoisePublicKey) {
	if a.multiHandler != nil {
		for _, h := range a.multiHandler.Handlers() {
			h.RemovePeer(key)
		}
	} else {
		a.handler.RemovePeer(key)
	}
	a.teardownPeer(key)
}

// RemovePeerFrom removes a peer from a specific handler and tears down
// its network plumbing.
func (a *Adapter) RemovePeerFrom(key NoisePublicKey, handler *Handler) {
	handler.RemovePeer(key)
	a.teardownPeer(key)
}

// Connect initiates a handshake to a peer at the given address.
// The peer must be authorized first via [AddPeer]. In single-key mode only;
// use [ConnectWith] in multi-key mode.
func (a *Adapter) Connect(key NoisePublicKey, addr *net.UDPAddr) error {
	return a.server.Connect(key, addr)
}

// ConnectWith initiates a handshake to a peer using a specific handler.
func (a *Adapter) ConnectWith(key NoisePublicKey, addr *net.UDPAddr, handler *Handler) error {
	return a.server.ConnectWith(key, addr, handler)
}

// PublicKey returns the adapter's WireGuard public key (single-key mode only).
// In multi-key mode, use [Handlers] to access individual public keys.
func (a *Adapter) PublicKey() NoisePublicKey {
	if a.handler == nil {
		panic("wg: PublicKey() not available in multi-key mode; use Handlers()")
	}
	return a.handler.PublicKey()
}

// Handler returns the underlying WireGuard protocol handler (single-key mode).
// Returns nil in multi-key mode.
func (a *Adapter) Handler() *Handler {
	return a.handler
}

// MultiHandler returns the multi-key handler, or nil in single-key mode.
func (a *Adapter) MultiHandler() *MultiHandler {
	return a.multiHandler
}

// Handlers returns all handlers. In single-key mode, returns a slice with
// the single handler. In multi-key mode, returns all handlers.
func (a *Adapter) Handlers() []*Handler {
	if a.multiHandler != nil {
		return a.multiHandler.Handlers()
	}
	return []*Handler{a.handler}
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

	if a.multiHandler != nil {
		return a.multiHandler.Close()
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
