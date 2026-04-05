package nat

import (
	"errors"
	"net/netip"
	"time"

	"github.com/KarpelesLab/pktkit"
)

// Helper is an optional NAT module loaded via [NAT.AddHelper].
type Helper interface {
	Name() string
	Close() error
}

// PacketHelper inspects and modifies packets flowing through the NAT.
// Used by ALGs (FTP, SIP, etc.) that need to rewrite embedded addresses
// in application-layer protocols.
type PacketHelper interface {
	Helper
	// MatchOutbound returns true if this helper handles connections to the
	// given protocol and destination port.
	MatchOutbound(proto uint8, dstPort uint16) bool
	// ProcessOutbound may modify an outbound packet after NAT translation.
	// It may call [NAT.AddExpectation] to register expected related connections.
	ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet
	// ProcessInbound may modify an inbound packet after reverse-NAT translation.
	ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet
}

// LocalHelper handles packets destined for the NAT's own inside IP address
// (e.g., UPnP control requests, SSDP discovery). Returns true if the packet
// was consumed and should not be processed further.
type LocalHelper interface {
	Helper
	HandleLocal(n *NAT, pkt pktkit.Packet) bool
}

// NATMapping provides a read-only view of a NAT mapping for use by helpers.
type NATMapping struct {
	Proto       uint8
	InsideIP    netip.Addr
	InsidePort  uint16
	OutsidePort uint16
}

// Expectation describes a future connection that the NAT should accept and
// translate automatically. Helpers create expectations for related connections
// (e.g., FTP data channels, RTP media streams).
type Expectation struct {
	Proto      uint8      // expected protocol (TCP/UDP)
	RemoteIP   netip.Addr // expected remote IP (zero = any)
	RemotePort uint16     // expected remote port (0 = any)
	InsideIP   netip.Addr // where to forward
	InsidePort uint16     // inside destination port
	Expires    time.Time
}

// PortForward is a static port mapping configured on the NAT.
type PortForward struct {
	Proto       uint8
	OutsidePort uint16
	InsideIP    netip.Addr
	InsidePort  uint16
	Description string
	Expires     time.Time // zero = permanent
}

// AddHelper registers a helper module with the NAT.
func (n *NAT) AddHelper(h Helper) {
	n.mu.Lock()
	n.helpers = append(n.helpers, h)
	n.mu.Unlock()
}

// AddExpectation registers an expected future connection.
func (n *NAT) AddExpectation(e Expectation) {
	n.mu.Lock()
	n.expectations = append(n.expectations, e)
	n.mu.Unlock()
}

// AddPortForward creates a static port mapping. Inbound connections to
// outsidePort are forwarded to insideIP:insidePort.
// Returns an error if the outside port is already forwarded to a different inside IP.
func (n *NAT) AddPortForward(pf PortForward) error {
	rk := natRevKey{proto: pf.Proto, port: pf.OutsidePort}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.forwards == nil {
		n.forwards = make(map[natRevKey]*PortForward)
	}
	// Reject if already forwarded to a different inside client.
	if existing, ok := n.forwards[rk]; ok {
		if existing.InsideIP != pf.InsideIP {
			return errors.New("port already forwarded to another host")
		}
	}
	pfCopy := pf
	n.forwards[rk] = &pfCopy
	return nil
}

// RemovePortForward removes a static port mapping.
func (n *NAT) RemovePortForward(proto uint8, outsidePort uint16) error {
	rk := natRevKey{proto: proto, port: outsidePort}
	n.mu.Lock()
	delete(n.forwards, rk)
	n.mu.Unlock()
	return nil
}

// ListPortForwards returns all active static port mappings.
func (n *NAT) ListPortForwards() []PortForward {
	n.mu.Lock()
	defer n.mu.Unlock()
	result := make([]PortForward, 0, len(n.forwards))
	now := time.Now()
	for _, pf := range n.forwards {
		if !pf.Expires.IsZero() && now.After(pf.Expires) {
			continue
		}
		result = append(result, *pf)
	}
	return result
}

// OutsideAddr returns the NAT's outside IP address. Useful for helpers that
// need to know the public IP.
func (n *NAT) OutsideAddr() netip.Addr {
	return n.outside.Addr().Addr()
}

// InsideAddr returns the NAT's inside IP address.
func (n *NAT) InsideAddr() netip.Addr {
	return n.inside.Addr().Addr()
}

// AllocOutsidePort allocates an outside port for use by helpers.
// Returns 0 if no ports are available.
func (n *NAT) AllocOutsidePort(proto uint8) uint16 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.allocPort()
}

// CreateMapping creates a NAT mapping for use by helpers. Returns the
// allocated outside port.
func (n *NAT) CreateMapping(proto uint8, insideIP netip.Addr, insidePort uint16) uint16 {
	k := natKey{proto: proto, ip: insideIP, port: insidePort}
	m := n.getOrCreateMapping(k)
	if m == nil {
		return 0
	}
	return m.outsidePort
}

// matchExpectation checks if an inbound connection matches any registered
// expectation. Returns the expectation and removes it if found.
func (n *NAT) matchExpectation(proto uint8, remoteIP netip.Addr, remotePort, dstPort uint16) *Expectation {
	now := time.Now()
	for i, e := range n.expectations {
		if now.After(e.Expires) {
			continue
		}
		if e.Proto != proto {
			continue
		}
		if e.RemoteIP.IsValid() && e.RemoteIP != remoteIP {
			continue
		}
		if e.RemotePort != 0 && e.RemotePort != remotePort {
			continue
		}
		// Match — remove and return.
		n.expectations = append(n.expectations[:i], n.expectations[i+1:]...)
		return &e
	}
	return nil
}

// matchForward checks if an inbound packet matches a static port forward.
func (n *NAT) matchForward(proto uint8, outsidePort uint16) *PortForward {
	rk := natRevKey{proto: proto, port: outsidePort}
	pf := n.forwards[rk]
	if pf == nil {
		return nil
	}
	if !pf.Expires.IsZero() && time.Now().After(pf.Expires) {
		delete(n.forwards, rk)
		return nil
	}
	return pf
}

// helperOutbound runs all matching packet helpers on an outbound packet.
func (n *NAT) helperOutbound(pkt pktkit.Packet, m *natMapping, proto uint8, dstPort uint16) pktkit.Packet {
	n.mu.Lock()
	helpers := n.helpers
	n.mu.Unlock()
	if len(helpers) == 0 {
		return pkt
	}
	nm := &NATMapping{
		Proto:       m.key.proto,
		InsideIP:    m.key.ip,
		InsidePort:  m.key.port,
		OutsidePort: m.outsidePort,
	}
	for _, h := range helpers {
		ph, ok := h.(PacketHelper)
		if !ok {
			continue
		}
		if ph.MatchOutbound(proto, dstPort) {
			pkt = ph.ProcessOutbound(n, pkt, nm)
		}
	}
	return pkt
}

// helperInbound runs all matching packet helpers on an inbound packet.
func (n *NAT) helperInbound(pkt pktkit.Packet, m *natMapping, proto uint8, dstPort uint16) pktkit.Packet {
	n.mu.Lock()
	helpers := n.helpers
	n.mu.Unlock()
	if len(helpers) == 0 {
		return pkt
	}
	nm := &NATMapping{
		Proto:       m.key.proto,
		InsideIP:    m.key.ip,
		InsidePort:  m.key.port,
		OutsidePort: m.outsidePort,
	}
	for _, h := range helpers {
		ph, ok := h.(PacketHelper)
		if !ok {
			continue
		}
		if ph.MatchOutbound(proto, dstPort) {
			pkt = ph.ProcessInbound(n, pkt, nm)
		}
	}
	return pkt
}

// handleLocal checks if any local helper consumes the packet.
func (n *NAT) handleLocal(pkt pktkit.Packet) bool {
	n.mu.Lock()
	helpers := n.helpers
	n.mu.Unlock()
	for _, h := range helpers {
		lh, ok := h.(LocalHelper)
		if !ok {
			continue
		}
		if lh.HandleLocal(n, pkt) {
			return true
		}
	}
	return false
}
