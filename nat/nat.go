// Package nat implements IPv4 network address translation between two L3 networks.
//
// Unlike the slirp package (which NATs to the real host network via net.Dial),
// this NAT operates entirely within the pktkit virtual network, translating
// addresses between an inside (private) and outside (public) L3 interface.
//
// It handles TCP, UDP, and ICMP (echo + error messages), including proper
// rewriting of embedded headers in ICMP error payloads.
package nat

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const (
	natPortMin         = 10000
	natPortMax         = 65535
	natTCPTimeout      = 5 * time.Minute
	natUDPTimeout      = 60 * time.Second
	natICMPTimeout     = 30 * time.Second
	natCleanupInterval = 30 * time.Second
	natTCPFinGrace     = 30 * time.Second

	protoICMP = 1
	protoTCP  = 6
	protoUDP  = 17
)

type natKey struct {
	ns    uint64 // namespace ID (0 = legacy single-device Inside())
	proto uint8
	ip    netip.Addr
	port  uint16 // src port for TCP/UDP, identifier for ICMP
}

type natRevKey struct {
	proto uint8
	port  uint16
}

type natMapping struct {
	key         natKey
	outsidePort uint16
	lastActive  int64 // UnixNano, updated from coarse clock
	finSeen     bool
	finTime     time.Time
}

// NAT performs IPv4 network address translation between two L3 networks.
// Inside() faces the private network (acts as default gateway).
// Outside() faces the upstream network (uses a public IP).
//
// For multi-tenant use (e.g. WireGuard), call ConnectL3 to create
// namespace-isolated inside L3Devices. Each namespace's connections are
// tracked independently, allowing overlapping inside IPs.
type NAT struct {
	inside  natSide
	outside natSide

	mu           sync.Mutex
	mappings     map[natKey]*natMapping
	reverse      map[natRevKey]*natMapping
	nextPort     uint16
	helpers      []Helper
	helperCount  atomic.Int32 // fast path: skip helper lock when 0
	forwards     map[natRevKey]*PortForward
	expectations []Expectation
	defragger    atomic.Pointer[Defragger]

	// Coarse clock updated every 250ms for lastActive timestamps.
	// Avoids a time.Now() syscall per packet on the hot path.
	coarseNow atomic.Int64 // UnixNano

	// Buffer pool for packet copies (avoids per-packet allocation).
	pktPool sync.Pool

	// Namespace-aware inside sides (for ConnectL3).
	nsMu      sync.RWMutex
	nsSides   map[uint64]*natNsSide
	nsCounter atomic.Uint64

	done      chan struct{}
	closeOnce sync.Once
}

// New creates a NAT with the given inside (private) and outside (public) addresses.
func New(insideAddr, outsideAddr netip.Prefix) *NAT {
	n := &NAT{
		mappings: make(map[natKey]*natMapping),
		reverse:  make(map[natRevKey]*natMapping),
		nextPort: natPortMin,
		nsSides:  make(map[uint64]*natNsSide),
		done:     make(chan struct{}),
		pktPool: sync.Pool{
			New: func() any {
				buf := make([]byte, 1536)
				return &buf
			},
		},
	}
	n.coarseNow.Store(time.Now().UnixNano())
	n.inside.nat = n
	n.inside.isInside = true
	n.inside.addr.Store(insideAddr)
	n.outside.nat = n
	n.outside.isInside = false
	n.outside.addr.Store(outsideAddr)
	go n.coarseClock()
	go n.maintenance()
	return n
}

// coarseClock updates the coarse timestamp every 250ms.
func (n *NAT) coarseClock() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-n.done:
			return
		case now := <-t.C:
			n.coarseNow.Store(now.UnixNano())
		}
	}
}

// nowCoarse returns the coarse cached timestamp.
func (n *NAT) nowCoarse() int64 {
	return n.coarseNow.Load()
}

// allocPacket returns a packet buffer from the pool, sized to pktLen.
func (n *NAT) allocPacket(pktLen int) (pktkit.Packet, *[]byte) {
	bufp := n.pktPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < pktLen {
		buf = make([]byte, pktLen)
		*bufp = buf
	}
	return pktkit.Packet(buf[:pktLen]), bufp
}

// freePacket returns a packet buffer to the pool.
func (n *NAT) freePacket(bufp *[]byte) {
	*bufp = (*bufp)[:cap(*bufp)]
	n.pktPool.Put(bufp)
}

// Inside returns the L3Device facing the private network.
func (n *NAT) Inside() pktkit.L3Device { return &n.inside }

// Outside returns the L3Device facing the upstream network.
func (n *NAT) Outside() pktkit.L3Device { return &n.outside }

// Close shuts down the NAT and stops the maintenance goroutine.
func (n *NAT) Close() error {
	n.closeOnce.Do(func() {
		close(n.done)
		n.mu.Lock()
		helpers := n.helpers
		n.helpers = nil
		n.helperCount.Store(0)
		if d := n.defragger.Swap(nil); d != nil {
			d.Close()
		}
		n.mu.Unlock()
		for _, h := range helpers {
			h.Close()
		}
	})
	return nil
}

// --- natSide implements pktkit.L3Device ---

type natSide struct {
	nat      *NAT
	isInside bool
	handler  atomic.Pointer[func(pktkit.Packet) error]
	addr     atomic.Value // netip.Prefix
}

func (s *natSide) SetHandler(h func(pktkit.Packet) error) { s.handler.Store(&h) }

func (s *natSide) Send(pkt pktkit.Packet) error {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	if s.isInside {
		s.nat.handleOutbound(0, pkt)
	} else {
		s.nat.handleInbound(pkt)
	}
	return nil
}

func (s *natSide) Addr() netip.Prefix {
	if v := s.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (s *natSide) SetAddr(p netip.Prefix) error {
	s.addr.Store(p)
	return nil
}

func (s *natSide) Close() error { return nil }

func (s *natSide) send(pkt pktkit.Packet) {
	if h := s.handler.Load(); h != nil {
		(*h)(pkt)
	}
}

// SendInside sends a raw IP packet out through the inside interface.
// Used by helpers (e.g., UPnP) that need to send responses to inside clients.
func (n *NAT) SendInside(pkt pktkit.Packet) {
	n.inside.send(pkt)
}

// sendInside routes a packet to the correct inside device based on namespace.
// ns=0 uses the legacy single Inside() device.
func (n *NAT) sendInside(ns uint64, pkt pktkit.Packet) {
	if ns == 0 {
		n.inside.send(pkt)
		return
	}
	n.nsMu.RLock()
	side := n.nsSides[ns]
	n.nsMu.RUnlock()
	if side != nil {
		side.send(pkt)
	}
}

// --- Namespace-aware inside sides ---

// natNsSide is a per-namespace inside L3Device created by ConnectL3.
type natNsSide struct {
	nat     *NAT
	ns      uint64
	handler atomic.Pointer[func(pktkit.Packet) error]
	addr    atomic.Value // netip.Prefix
}

func (s *natNsSide) SetHandler(h func(pktkit.Packet) error) { s.handler.Store(&h) }

func (s *natNsSide) Send(pkt pktkit.Packet) error {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return nil
	}
	s.nat.handleOutbound(s.ns, pkt)
	return nil
}

func (s *natNsSide) Addr() netip.Prefix {
	if v := s.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (s *natNsSide) SetAddr(p netip.Prefix) error {
	s.addr.Store(p)
	return nil
}

func (s *natNsSide) Close() error { return nil }

func (s *natNsSide) send(pkt pktkit.Packet) {
	if h := s.handler.Load(); h != nil {
		(*h)(pkt)
	}
}

// ConnectL3 implements [pktkit.L3Connector]. It creates a namespace-isolated
// inside L3Device. Packets from the device are tracked with a unique namespace
// ID, so multiple devices can use overlapping inside IPs without conflict.
// The returned cleanup function removes the namespace and its mappings.
func (n *NAT) ConnectL3(dev pktkit.L3Device) (func() error, error) {
	nsID := n.nsCounter.Add(1)

	side := &natNsSide{nat: n, ns: nsID}
	side.addr.Store(n.inside.Addr())

	// Wire bidirectionally.
	pktkit.ConnectL3(side, dev)

	n.nsMu.Lock()
	n.nsSides[nsID] = side
	n.nsMu.Unlock()

	return func() error {
		n.nsMu.Lock()
		delete(n.nsSides, nsID)
		n.nsMu.Unlock()
		n.cleanupNamespace(nsID)
		return nil
	}, nil
}

// cleanupNamespace removes all mappings belonging to a namespace.
func (n *NAT) cleanupNamespace(ns uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for k, m := range n.mappings {
		if k.ns == ns {
			delete(n.mappings, k)
			delete(n.reverse, natRevKey{proto: k.proto, port: m.outsidePort})
		}
	}
}

// --- Outbound: inside → outside ---

func (n *NAT) handleOutbound(ns uint64, pkt pktkit.Packet) {
	// Defragment if enabled (atomic load — no lock needed on the hot path).
	if d := n.defragger.Load(); d != nil {
		pkt = d.Process(pkt)
		if pkt == nil {
			return // fragment buffered, waiting for more
		}
	}

	// Check local helpers for packets addressed to the NAT's inside IP.
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	if dstIP == n.InsideAddr() {
		if n.handleLocal(pkt) {
			return
		}
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 {
		return
	}
	proto := pkt[9]

	switch proto {
	case protoTCP, protoUDP:
		if len(pkt) < ihl+4 {
			return
		}
		n.handleOutboundTCPUDP(ns, pkt, ihl, proto)
	case protoICMP:
		if len(pkt) < ihl+8 {
			return
		}
		n.handleOutboundICMP(ns, pkt, ihl)
	}
}

func (n *NAT) handleOutboundTCPUDP(ns uint64, pkt pktkit.Packet, ihl int, proto uint8) {
	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))

	k := natKey{ns: ns, proto: proto, ip: srcIP, port: srcPort}
	m := n.getOrCreateMapping(k)
	if m == nil {
		return
	}

	outsideIP := n.outside.Addr().Addr()

	// Track TCP FIN/RST for cleanup.
	if proto == protoTCP && len(pkt) >= ihl+14 {
		flags := pkt[ihl+13]
		if flags&0x05 != 0 {
			n.mu.Lock()
			if !m.finSeen {
				m.finSeen = true
				m.finTime = time.Now()
			}
			n.mu.Unlock()
		}
	}

	out, bufp := n.allocPacket(len(pkt))
	copy(out, pkt)

	oldSrcIP := [4]byte(out[12:16])
	newSrcIP := outsideIP.As4()
	copy(out[12:16], newSrcIP[:])

	oldPort := binary.BigEndian.Uint16(out[ihl : ihl+2])
	binary.BigEndian.PutUint16(out[ihl:ihl+2], m.outsidePort)

	updateIPChecksum(out, oldSrcIP, newSrcIP)

	if proto == protoTCP && len(out) >= ihl+18 {
		updateL4Checksum(out, ihl+16, oldSrcIP, newSrcIP, oldPort, m.outsidePort)
	} else if proto == protoUDP && len(out) >= ihl+8 {
		csumOff := ihl + 6
		if binary.BigEndian.Uint16(out[csumOff:csumOff+2]) != 0 {
			updateL4Checksum(out, csumOff, oldSrcIP, newSrcIP, oldPort, m.outsidePort)
		}
	}

	// Run packet helpers after NAT translation.
	dstPort := binary.BigEndian.Uint16(out[ihl+2 : ihl+4])
	out = n.helperOutbound(out, m, proto, dstPort)

	n.outside.send(out)
	n.freePacket(bufp)
}

func (n *NAT) handleOutboundICMP(ns uint64, pkt pktkit.Packet, ihl int) {
	icmpType := pkt[ihl]
	if icmpType != 8 { // only handle Echo Request outbound
		return
	}

	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	id := binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])

	k := natKey{ns: ns, proto: protoICMP, ip: srcIP, port: id}
	m := n.getOrCreateMapping(k)
	if m == nil {
		return
	}

	outsideIP := n.outside.Addr().Addr()
	out, bufp := n.allocPacket(len(pkt))
	copy(out, pkt)

	oldSrcIP := [4]byte(out[12:16])
	newSrcIP := outsideIP.As4()
	copy(out[12:16], newSrcIP[:])

	oldID := binary.BigEndian.Uint16(out[ihl+4 : ihl+6])
	binary.BigEndian.PutUint16(out[ihl+4:ihl+6], m.outsidePort)

	updateIPChecksum(out, oldSrcIP, newSrcIP)
	updateICMPChecksum(out, ihl, oldID, m.outsidePort)

	n.outside.send(out)
	n.freePacket(bufp)
}

// --- Inbound: outside → inside ---

func (n *NAT) handleInbound(pkt pktkit.Packet) {
	// Defragment if enabled (atomic load — no lock needed on the hot path).
	if d := n.defragger.Load(); d != nil {
		pkt = d.Process(pkt)
		if pkt == nil {
			return
		}
	}

	// Check local helpers (packets to the NAT's own outside IP).
	if n.handleLocal(pkt) {
		return
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 {
		return
	}
	proto := pkt[9]

	switch proto {
	case protoTCP, protoUDP:
		if len(pkt) < ihl+4 {
			return
		}
		n.handleInboundTCPUDP(pkt, ihl, proto)
	case protoICMP:
		if len(pkt) < ihl+8 {
			return
		}
		n.handleInboundICMP(pkt, ihl)
	}
}

func (n *NAT) handleInboundTCPUDP(pkt pktkit.Packet, ihl int, proto uint8) {
	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])

	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))

	rk := natRevKey{proto: proto, port: dstPort}
	nowTS := n.nowCoarse()
	n.mu.Lock()
	m := n.reverse[rk]
	if m != nil {
		m.lastActive = nowTS
	}
	// No existing mapping — check expectations and port forwards.
	if m == nil {
		if e := n.matchExpectation(proto, srcIP, srcPort, dstPort); e != nil {
			// Create mapping from expectation, reusing the outside port that
			// the remote is already sending to (no separate port allocation needed).
			k := natKey{proto: proto, ip: e.InsideIP, port: e.InsidePort}
			m = &natMapping{
				key:         k,
				outsidePort: dstPort,
				lastActive:  nowTS,
			}
			n.mappings[k] = m
			n.reverse[rk] = m
		}
	}
	if m == nil {
		if pf := n.matchForward(proto, dstPort); pf != nil {
			// Create mapping from port forward.
			k := natKey{proto: proto, ip: pf.InsideIP, port: pf.InsidePort}
			m = &natMapping{
				key:         k,
				outsidePort: dstPort,
				lastActive:  nowTS,
			}
			n.mappings[k] = m
			n.reverse[rk] = m
		}
	}
	n.mu.Unlock()
	if m == nil {
		return
	}

	if proto == protoTCP && len(pkt) >= ihl+14 {
		flags := pkt[ihl+13]
		if flags&0x05 != 0 {
			n.mu.Lock()
			if !m.finSeen {
				m.finSeen = true
				m.finTime = time.Now()
			}
			n.mu.Unlock()
		}
	}

	out, bufp := n.allocPacket(len(pkt))
	copy(out, pkt)

	oldDstIP := [4]byte(out[16:20])
	newDstIP := m.key.ip.As4()
	copy(out[16:20], newDstIP[:])

	oldPort := binary.BigEndian.Uint16(out[ihl+2 : ihl+4])
	binary.BigEndian.PutUint16(out[ihl+2:ihl+4], m.key.port)

	updateIPChecksumDst(out, oldDstIP, newDstIP)

	if proto == protoTCP && len(out) >= ihl+18 {
		updateL4Checksum(out, ihl+16, oldDstIP, newDstIP, oldPort, m.key.port)
	} else if proto == protoUDP && len(out) >= ihl+8 {
		csumOff := ihl + 6
		if binary.BigEndian.Uint16(out[csumOff:csumOff+2]) != 0 {
			updateL4Checksum(out, csumOff, oldDstIP, newDstIP, oldPort, m.key.port)
		}
	}

	// Run packet helpers after reverse-NAT.
	origDstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4]) // pre-NAT dst port
	out = n.helperInbound(out, m, proto, origDstPort)

	n.sendInside(m.key.ns, out)
	n.freePacket(bufp)
}

func (n *NAT) handleInboundICMP(pkt pktkit.Packet, ihl int) {
	icmpType := pkt[ihl]

	switch icmpType {
	case 0: // Echo Reply
		id := binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6])
		rk := natRevKey{proto: protoICMP, port: id}
		n.mu.Lock()
		m := n.reverse[rk]
		if m != nil {
			m.lastActive = n.nowCoarse()
		}
		n.mu.Unlock()
		if m == nil {
			return
		}

		out, bufp := n.allocPacket(len(pkt))
		copy(out, pkt)

		oldDstIP := [4]byte(out[16:20])
		newDstIP := m.key.ip.As4()
		copy(out[16:20], newDstIP[:])

		oldID := binary.BigEndian.Uint16(out[ihl+4 : ihl+6])
		binary.BigEndian.PutUint16(out[ihl+4:ihl+6], m.key.port)

		updateIPChecksumDst(out, oldDstIP, newDstIP)
		updateICMPChecksum(out, ihl, oldID, m.key.port)

		n.sendInside(m.key.ns, out)
		n.freePacket(bufp)

	case 3, 11, 12: // Dest Unreachable, Time Exceeded, Parameter Problem
		n.handleInboundICMPError(pkt, ihl)
	}
}

// handleInboundICMPError processes ICMP error messages by rewriting the
// embedded original packet header to point back to the inside client.
func (n *NAT) handleInboundICMPError(pkt pktkit.Packet, outerIHL int) {
	// ICMP error payload starts at outerIHL + 8 (type+code+csum+unused/pointer).
	embOff := outerIHL + 8
	if len(pkt) < embOff+20 {
		return
	}
	embIHL := int(pkt[embOff]&0x0F) * 4
	if embIHL < 20 || len(pkt) < embOff+embIHL+4 {
		return
	}

	embProto := pkt[embOff+9]
	var embPort uint16
	switch embProto {
	case protoTCP, protoUDP:
		embPort = binary.BigEndian.Uint16(pkt[embOff+embIHL : embOff+embIHL+2])
	case protoICMP:
		if len(pkt) < embOff+embIHL+6 {
			return
		}
		embPort = binary.BigEndian.Uint16(pkt[embOff+embIHL+4 : embOff+embIHL+6])
	default:
		return
	}

	rk := natRevKey{proto: embProto, port: embPort}
	n.mu.Lock()
	m := n.reverse[rk]
	if m != nil {
		m.lastActive = n.nowCoarse()
	}
	n.mu.Unlock()
	if m == nil {
		return
	}

	out, bufp := n.allocPacket(len(pkt))
	copy(out, pkt)

	// Rewrite outer destination IP to inside client.
	oldOuterDstIP := [4]byte(out[16:20])
	newOuterDstIP := m.key.ip.As4()
	copy(out[16:20], newOuterDstIP[:])
	updateIPChecksumDst(out, oldOuterDstIP, newOuterDstIP)

	// Rewrite embedded source IP from outside IP back to inside client.
	copy(out[embOff+12:embOff+16], newOuterDstIP[:])

	// Rewrite embedded source port back to inside client port.
	switch embProto {
	case protoTCP, protoUDP:
		binary.BigEndian.PutUint16(out[embOff+embIHL:embOff+embIHL+2], m.key.port)
	case protoICMP:
		binary.BigEndian.PutUint16(out[embOff+embIHL+4:embOff+embIHL+6], m.key.port)
	}

	// Recalculate outer ICMP checksum from scratch (covers modified embedded data).
	icmpData := out[outerIHL:]
	binary.BigEndian.PutUint16(icmpData[2:4], 0)
	binary.BigEndian.PutUint16(icmpData[2:4], pktkit.Checksum(icmpData))

	n.sendInside(m.key.ns, out)
	n.freePacket(bufp)
}

// --- Mapping management ---

func (n *NAT) getOrCreateMapping(k natKey) *natMapping {
	nowTS := n.nowCoarse()
	n.mu.Lock()
	defer n.mu.Unlock()

	if m, ok := n.mappings[k]; ok {
		m.lastActive = nowTS
		return m
	}

	port := n.allocPort()
	if port == 0 {
		return nil
	}

	m := &natMapping{
		key:         k,
		outsidePort: port,
		lastActive:  nowTS,
	}
	n.mappings[k] = m
	n.reverse[natRevKey{proto: k.proto, port: port}] = m
	return m
}

func (n *NAT) allocPort() uint16 {
	start := n.nextPort
	for {
		p := n.nextPort
		n.nextPort++
		if n.nextPort > natPortMax {
			n.nextPort = natPortMin
		}
		inUse := false
		for _, proto := range []uint8{protoTCP, protoUDP, protoICMP} {
			if _, ok := n.reverse[natRevKey{proto: proto, port: p}]; ok {
				inUse = true
				break
			}
		}
		if !inUse {
			return p
		}
		if n.nextPort == start {
			return 0
		}
	}
}

func (n *NAT) maintenance() {
	ticker := time.NewTicker(natCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
		}
		now := time.Now()
		nowNano := now.UnixNano()
		n.mu.Lock()
		for k, m := range n.mappings {
			var timeout time.Duration
			switch k.proto {
			case protoTCP:
				if m.finSeen && now.Sub(m.finTime) > natTCPFinGrace {
					timeout = 0
				} else {
					timeout = natTCPTimeout
				}
			case protoUDP:
				timeout = natUDPTimeout
			case protoICMP:
				timeout = natICMPTimeout
			default:
				timeout = natUDPTimeout
			}
			if timeout == 0 || nowNano-m.lastActive > int64(timeout) {
				delete(n.mappings, k)
				delete(n.reverse, natRevKey{proto: k.proto, port: m.outsidePort})
			}
		}
		n.mu.Unlock()
	}
}

// --- Incremental checksum helpers ---

func checksumAdjust(oldCsum uint16, oldVal, newVal uint16) uint16 {
	sum := uint32(^oldCsum) + uint32(^oldVal) + uint32(newVal)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func updateIPChecksum(pkt pktkit.Packet, oldIP, newIP [4]byte) {
	csum := binary.BigEndian.Uint16(pkt[10:12])
	csum = checksumAdjust(csum,
		binary.BigEndian.Uint16(oldIP[0:2]),
		binary.BigEndian.Uint16(newIP[0:2]))
	csum = checksumAdjust(csum,
		binary.BigEndian.Uint16(oldIP[2:4]),
		binary.BigEndian.Uint16(newIP[2:4]))
	binary.BigEndian.PutUint16(pkt[10:12], csum)
}

func updateIPChecksumDst(pkt pktkit.Packet, oldIP, newIP [4]byte) {
	updateIPChecksum(pkt, oldIP, newIP)
}

func updateL4Checksum(pkt pktkit.Packet, csumOff int, oldIP, newIP [4]byte, oldPort, newPort uint16) {
	csum := binary.BigEndian.Uint16(pkt[csumOff : csumOff+2])
	csum = checksumAdjust(csum,
		binary.BigEndian.Uint16(oldIP[0:2]),
		binary.BigEndian.Uint16(newIP[0:2]))
	csum = checksumAdjust(csum,
		binary.BigEndian.Uint16(oldIP[2:4]),
		binary.BigEndian.Uint16(newIP[2:4]))
	csum = checksumAdjust(csum, oldPort, newPort)
	binary.BigEndian.PutUint16(pkt[csumOff:csumOff+2], csum)
}

func updateICMPChecksum(pkt pktkit.Packet, ihl int, oldID, newID uint16) {
	csumOff := ihl + 2
	csum := binary.BigEndian.Uint16(pkt[csumOff : csumOff+2])
	csum = checksumAdjust(csum, oldID, newID)
	binary.BigEndian.PutUint16(pkt[csumOff:csumOff+2], csum)
}
