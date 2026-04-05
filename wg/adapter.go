package wg

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/KarpelesLab/pktkit"
)

// AdapterConfig configures a WireGuard [Adapter].
type AdapterConfig struct {
	// PrivateKey is the local WireGuard identity. If zero, a new key is generated.
	PrivateKey NoisePrivateKey

	// Connector receives per-peer L2Devices. Use an [*pktkit.L2Hub] for shared
	// networking or a [slirp.Provider] for per-peer namespace isolation.
	Connector pktkit.L2Connector

	// Addr is the IP prefix for the gateway side of each peer's link
	// (e.g. "10.0.0.1/24"). Each peer's PipeL3 gets this prefix so the
	// L2Adapter can respond to ARP for the gateway address.
	Addr netip.Prefix

	// OnUnknownPeer is called when an unauthorized peer initiates a handshake.
	// Call [Adapter.AddPeer] from this callback (or later) to authorize it,
	// then call [Adapter.AcceptUnknownPeer] to complete the handshake.
	OnUnknownPeer func(key NoisePublicKey, addr *net.UDPAddr, packet []byte)
}

// Adapter bridges WireGuard peers to pktkit's L2 networking. Each peer that
// completes a handshake gets a per-peer L3Device wrapped in an L2Adapter
// and connected to the configured L2Connector (hub or namespace provider).
//
// Decrypted IP packets from peers are injected into their L3Device, which
// the L2Adapter frames and forwards to the connector. Outgoing IP packets
// from the connector flow back through the L2Adapter, are encrypted by the
// WireGuard handler, and sent via the PacketConn.
type Adapter struct {
	handler   *Handler
	server    *Server
	connector pktkit.L2Connector
	addr      netip.Prefix

	mu    sync.RWMutex
	peers map[NoisePublicKey]*wgPeer
}

// wgPeer tracks one connected WireGuard peer's network plumbing.
type wgPeer struct {
	key     NoisePublicKey
	pipe    *pktkit.PipeL3
	adapter *pktkit.L2Adapter
	cleanup func() error // from L2Connector.ConnectL2
}

// NewAdapter creates a WireGuard adapter that connects peers to the given
// L2Connector. Call [Adapter.Serve] with a net.PacketConn to start.
func NewAdapter(cfg AdapterConfig) (*Adapter, error) {
	if cfg.Connector == nil {
		return nil, fmt.Errorf("wg: Connector is required")
	}

	h, err := NewHandler(Config{
		PrivateKey:    cfg.PrivateKey,
		OnUnknownPeer: cfg.OnUnknownPeer,
	})
	if err != nil {
		return nil, err
	}

	a := &Adapter{
		handler:   h,
		connector: cfg.Connector,
		addr:      cfg.Addr,
		peers:     make(map[NoisePublicKey]*wgPeer),
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
		p.adapter.Close()
		if p.cleanup != nil {
			p.cleanup()
		}
	}

	return a.handler.Close()
}

// onPeerConnected is called by the Server when a handshake completes.
// It creates the per-peer L3 pipe + L2Adapter and wires it to the connector.
func (a *Adapter) onPeerConnected(key NoisePublicKey) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Already wired — nothing to do (rekey doesn't need new plumbing).
	if _, exists := a.peers[key]; exists {
		return
	}

	pipe := pktkit.NewPipeL3(a.addr)

	// Outgoing: packets from the network side → encrypt → send to peer.
	pipe.SetHandler(func(pkt pktkit.Packet) error {
		return a.server.Send(pkt, key)
	})

	l2a := pktkit.NewL2Adapter(pipe, nil)

	cleanup, err := a.connector.ConnectL2(l2a)
	if err != nil {
		l2a.Close()
		return
	}

	a.peers[key] = &wgPeer{
		key:     key,
		pipe:    pipe,
		adapter: l2a,
		cleanup: cleanup,
	}
}

// onPacket is called by the Server when a decrypted IP packet arrives.
func (a *Adapter) onPacket(data []byte, key NoisePublicKey) {
	a.mu.RLock()
	p := a.peers[key]
	a.mu.RUnlock()

	if p == nil {
		return
	}

	// Deliver the decrypted IP packet to the peer's L3 pipe.
	p.pipe.Send(pktkit.Packet(data))
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
		p.adapter.Close()
		if p.cleanup != nil {
			p.cleanup()
		}
	}
}
