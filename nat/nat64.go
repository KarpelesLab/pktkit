// NAT64 translates between IPv6 and IPv4 packets, allowing IPv6-only clients
// to reach IPv4 destinations via IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
//
// Inside() faces the IPv6 network; Outside() faces the IPv4 network.
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
	protoICMPv6 = 58

	ipv6HeaderLen = 40
	ipv4MinHeader = 20
)

// nat64Key identifies a mapping by the inside client's IPv6 address and port.
type nat64Key struct {
	proto uint8
	ip    netip.Addr // client IPv6 address
	port  uint16     // src port for TCP/UDP, identifier for ICMP
}

// nat64RevKey identifies a mapping by outside protocol and port.
type nat64RevKey struct {
	proto uint8
	port  uint16
}

// nat64Mapping tracks one NAT64 translation entry.
type nat64Mapping struct {
	key         nat64Key
	outsidePort uint16
	lastActive  time.Time
	finSeen     bool
	finTime     time.Time
}

// NAT64 performs IPv6-to-IPv4 network address translation.
// Inside() faces the IPv6 network; Outside() faces the IPv4 network.
type NAT64 struct {
	inside  nat64Side
	outside nat64Side

	mu       sync.Mutex
	mappings map[nat64Key]*nat64Mapping
	reverse  map[nat64RevKey]*nat64Mapping
	nextPort uint16

	done      chan struct{}
	closeOnce sync.Once
}

// NewNAT64 creates a NAT64 with the given inside (IPv6) and outside (IPv4) addresses.
func NewNAT64(insideAddr, outsideAddr netip.Prefix) *NAT64 {
	n := &NAT64{
		mappings: make(map[nat64Key]*nat64Mapping),
		reverse:  make(map[nat64RevKey]*nat64Mapping),
		nextPort: natPortMin,
		done:     make(chan struct{}),
	}
	n.inside.nat = n
	n.inside.isInside = true
	n.inside.addr.Store(insideAddr)
	n.outside.nat = n
	n.outside.isInside = false
	n.outside.addr.Store(outsideAddr)
	go n.maintenance()
	return n
}

// Inside returns the L3Device facing the IPv6 network.
func (n *NAT64) Inside() pktkit.L3Device { return &n.inside }

// Outside returns the L3Device facing the IPv4 network.
func (n *NAT64) Outside() pktkit.L3Device { return &n.outside }

// Close shuts down the NAT64 and stops the maintenance goroutine.
func (n *NAT64) Close() error {
	n.closeOnce.Do(func() {
		close(n.done)
	})
	return nil
}

// --- nat64Side implements pktkit.L3Device ---

type nat64Side struct {
	nat      *NAT64
	isInside bool
	handler  atomic.Pointer[func(pktkit.Packet) error]
	addr     atomic.Value // netip.Prefix
}

func (s *nat64Side) SetHandler(h func(pktkit.Packet) error) { s.handler.Store(&h) }

func (s *nat64Side) Send(pkt pktkit.Packet) error {
	if s.isInside {
		// Expect IPv6 packets on the inside.
		if len(pkt) < ipv6HeaderLen || pkt[0]>>4 != 6 {
			return nil
		}
		s.nat.handleOutbound(pkt)
	} else {
		// Expect IPv4 packets on the outside.
		if len(pkt) < ipv4MinHeader || pkt[0]>>4 != 4 {
			return nil
		}
		s.nat.handleInbound(pkt)
	}
	return nil
}

func (s *nat64Side) Addr() netip.Prefix {
	if v := s.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (s *nat64Side) SetAddr(p netip.Prefix) error {
	s.addr.Store(p)
	return nil
}

func (s *nat64Side) Close() error { return nil }

func (s *nat64Side) send(pkt pktkit.Packet) {
	if h := s.handler.Load(); h != nil {
		(*h)(pkt)
	}
}

// --- Helper functions ---

// isIPv4Mapped checks if an IPv6 address is ::ffff:x.x.x.x
func isIPv4Mapped(addr netip.Addr) bool {
	b := addr.As16()
	for i := 0; i < 10; i++ {
		if b[i] != 0 {
			return false
		}
	}
	return b[10] == 0xff && b[11] == 0xff
}

// ipv4FromMapped extracts the IPv4 address from ::ffff:x.x.x.x
func ipv4FromMapped(addr netip.Addr) netip.Addr {
	b := addr.As16()
	return netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
}

// ipv4ToMapped converts an IPv4 address to ::ffff:x.x.x.x
func ipv4ToMapped(addr netip.Addr) netip.Addr {
	v4 := addr.As4()
	var b [16]byte
	b[10] = 0xff
	b[11] = 0xff
	b[12] = v4[0]
	b[13] = v4[1]
	b[14] = v4[2]
	b[15] = v4[3]
	return netip.AddrFrom16(b)
}

// computeTransportChecksum calculates a TCP or UDP checksum from scratch
// over the given pseudo-header parameters and transport segment data.
// The checksum field in transport must already be zeroed.
func computeTransportChecksum(proto uint8, srcIP, dstIP netip.Addr, transport []byte) uint16 {
	length := uint16(len(transport))
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.Protocol(proto), srcIP, dstIP, length)
	dataCsum := pktkit.Checksum(transport)
	// Combine: both are one's complement partial sums (un-complemented).
	sum := uint32(^phCsum) + uint32(^dataCsum)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// computeICMPv6Checksum calculates the ICMPv6 checksum which includes an
// IPv6 pseudo-header. The checksum field in icmpData must already be zeroed.
func computeICMPv6Checksum(srcIP, dstIP netip.Addr, icmpData []byte) uint16 {
	length := uint16(len(icmpData))
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolICMPv6, srcIP, dstIP, length)
	dataCsum := pktkit.Checksum(icmpData)
	sum := uint32(^phCsum) + uint32(^dataCsum)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// --- Outbound: IPv6 (inside) → IPv4 (outside) ---

func (n *NAT64) handleOutbound(pkt pktkit.Packet) {
	// Parse IPv6 header.
	if len(pkt) < ipv6HeaderLen {
		return
	}

	dstIPv6 := netip.AddrFrom16([16]byte(pkt[24:40]))
	if !isIPv4Mapped(dstIPv6) {
		return // not destined for an IPv4 host
	}
	dstIPv4 := ipv4FromMapped(dstIPv6)

	hopLimit := pkt[7]
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	srcIPv6 := netip.AddrFrom16([16]byte(pkt[8:24]))

	if len(pkt) < ipv6HeaderLen+payloadLen {
		return
	}

	// Walk extension headers to find the actual transport protocol.
	nextHeader := pkt[6]
	transportOff := ipv6HeaderLen
	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			if transportOff+2 > len(pkt) {
				return
			}
			extLen := int(pkt[transportOff+1]+1) * 8
			nextHeader = pkt[transportOff]
			transportOff += extLen
			continue
		case 44: // Fragment Header (8 bytes fixed)
			if transportOff+8 > len(pkt) {
				return
			}
			nextHeader = pkt[transportOff]
			transportOff += 8
			continue
		}
		break
	}

	if transportOff > len(pkt) {
		return
	}
	transport := pkt[transportOff:]

	switch nextHeader {
	case protoTCP, protoUDP:
		n.handleOutboundTCPUDP(transport, nextHeader, srcIPv6, dstIPv4, hopLimit)
	case protoICMPv6:
		n.handleOutboundICMPv6(transport, srcIPv6, dstIPv4, hopLimit)
	}
}

func (n *NAT64) handleOutboundTCPUDP(transport []byte, proto uint8, srcIPv6 netip.Addr, dstIPv4 netip.Addr, hopLimit uint8) {
	if len(transport) < 4 {
		return
	}
	srcPort := binary.BigEndian.Uint16(transport[0:2])

	k := nat64Key{proto: proto, ip: srcIPv6, port: srcPort}
	m := n.getOrCreateMapping(k)
	if m == nil {
		return
	}

	// Track TCP FIN/RST.
	if proto == protoTCP && len(transport) >= 14 {
		flags := transport[13]
		if flags&0x05 != 0 { // FIN or RST
			n.mu.Lock()
			if !m.finSeen {
				m.finSeen = true
				m.finTime = time.Now()
			}
			n.mu.Unlock()
		}
	}

	outsideIP := n.outside.Addr().Addr()

	// Build IPv4 packet: 20-byte header + transport.
	totalLen := ipv4MinHeader + len(transport)
	out := make(pktkit.Packet, totalLen)

	// IPv4 header.
	out[0] = 0x45 // version=4, IHL=5
	// out[1] = 0 // DSCP/ECN
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	// out[4:6] = 0 // identification
	// out[6:8] = 0 // flags + fragment offset
	out[8] = hopLimit // TTL
	out[9] = proto     // protocol
	// out[10:12] = 0 // header checksum (computed below)
	srcV4 := outsideIP.As4()
	dstV4 := dstIPv4.As4()
	copy(out[12:16], srcV4[:])
	copy(out[16:20], dstV4[:])

	// Copy transport data.
	copy(out[ipv4MinHeader:], transport)

	// Rewrite source port to mapped port.
	binary.BigEndian.PutUint16(out[ipv4MinHeader:ipv4MinHeader+2], m.outsidePort)

	// Zero the transport checksum, then recompute.
	transportSlice := out[ipv4MinHeader:]
	if proto == protoTCP && len(transportSlice) >= 18 {
		binary.BigEndian.PutUint16(transportSlice[16:18], 0)
		csum := computeTransportChecksum(proto, outsideIP, dstIPv4, transportSlice)
		binary.BigEndian.PutUint16(transportSlice[16:18], csum)
	} else if proto == protoUDP && len(transportSlice) >= 8 {
		binary.BigEndian.PutUint16(transportSlice[6:8], 0)
		csum := computeTransportChecksum(proto, outsideIP, dstIPv4, transportSlice)
		if csum == 0 {
			csum = 0xffff // UDP: 0 means no checksum, use 0xffff instead
		}
		binary.BigEndian.PutUint16(transportSlice[6:8], csum)
	}

	// Compute IPv4 header checksum.
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], pktkit.Checksum(out[:ipv4MinHeader]))

	n.outside.send(out)
}

func (n *NAT64) handleOutboundICMPv6(icmpData []byte, srcIPv6 netip.Addr, dstIPv4 netip.Addr, hopLimit uint8) {
	if len(icmpData) < 8 {
		return
	}

	icmpType := icmpData[0]

	switch icmpType {
	case 128: // ICMPv6 Echo Request → ICMPv4 Echo Request (type 8)
		n.handleOutboundEchoRequest(icmpData, srcIPv6, dstIPv4, hopLimit)
	// Other ICMPv6 types are not translated outbound in a NAT64.
	}
}

func (n *NAT64) handleOutboundEchoRequest(icmpData []byte, srcIPv6 netip.Addr, dstIPv4 netip.Addr, hopLimit uint8) {
	if len(icmpData) < 8 {
		return
	}

	id := binary.BigEndian.Uint16(icmpData[4:6])

	k := nat64Key{proto: protoICMP, ip: srcIPv6, port: id}
	m := n.getOrCreateMapping(k)
	if m == nil {
		return
	}

	outsideIP := n.outside.Addr().Addr()

	// Build ICMPv4 Echo Request.
	totalLen := ipv4MinHeader + len(icmpData)
	out := make(pktkit.Packet, totalLen)

	// IPv4 header.
	out[0] = 0x45
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))
	out[8] = hopLimit
	out[9] = protoICMP
	srcV4 := outsideIP.As4()
	dstV4 := dstIPv4.As4()
	copy(out[12:16], srcV4[:])
	copy(out[16:20], dstV4[:])

	// Copy ICMP data and translate.
	copy(out[ipv4MinHeader:], icmpData)
	icmpOut := out[ipv4MinHeader:]
	icmpOut[0] = 8 // ICMPv4 Echo Request
	icmpOut[1] = 0 // code stays 0
	binary.BigEndian.PutUint16(icmpOut[4:6], m.outsidePort)

	// ICMPv4 checksum (no pseudo-header).
	binary.BigEndian.PutUint16(icmpOut[2:4], 0)
	binary.BigEndian.PutUint16(icmpOut[2:4], pktkit.Checksum(icmpOut))

	// IPv4 header checksum.
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], pktkit.Checksum(out[:ipv4MinHeader]))

	n.outside.send(out)
}

// --- Inbound: IPv4 (outside) → IPv6 (inside) ---

func (n *NAT64) handleInbound(pkt pktkit.Packet) {
	if len(pkt) < ipv4MinHeader {
		return
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < ipv4MinHeader || len(pkt) < ihl {
		return
	}

	proto := pkt[9]
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen < ihl || len(pkt) < totalLen {
		return
	}
	transport := pkt[ihl:totalLen]
	ttl := pkt[8]
	srcIPv4 := netip.AddrFrom4([4]byte(pkt[12:16]))

	switch proto {
	case protoTCP, protoUDP:
		n.handleInboundTCPUDP(transport, proto, srcIPv4, ttl)
	case protoICMP:
		n.handleInboundICMP(transport, srcIPv4, ttl)
	}
}

func (n *NAT64) handleInboundTCPUDP(transport []byte, proto uint8, srcIPv4 netip.Addr, ttl uint8) {
	if len(transport) < 4 {
		return
	}
	dstPort := binary.BigEndian.Uint16(transport[2:4])

	rk := nat64RevKey{proto: proto, port: dstPort}
	n.mu.Lock()
	m := n.reverse[rk]
	if m != nil {
		m.lastActive = time.Now()
	}
	n.mu.Unlock()
	if m == nil {
		return
	}

	// Track TCP FIN/RST.
	if proto == protoTCP && len(transport) >= 14 {
		flags := transport[13]
		if flags&0x05 != 0 {
			n.mu.Lock()
			if !m.finSeen {
				m.finSeen = true
				m.finTime = time.Now()
			}
			n.mu.Unlock()
		}
	}

	srcIPv6 := ipv4ToMapped(srcIPv4)
	dstIPv6 := m.key.ip

	// Build IPv6 packet: 40-byte header + transport.
	outLen := ipv6HeaderLen + len(transport)
	out := make(pktkit.Packet, outLen)

	// IPv6 header.
	out[0] = 0x60 // version=6
	// out[1:4] = 0 // traffic class + flow label
	binary.BigEndian.PutUint16(out[4:6], uint16(len(transport)))
	out[6] = proto // next header
	out[7] = ttl   // hop limit
	srcV6 := srcIPv6.As16()
	dstV6 := dstIPv6.As16()
	copy(out[8:24], srcV6[:])
	copy(out[24:40], dstV6[:])

	// Copy transport data.
	copy(out[ipv6HeaderLen:], transport)

	// Rewrite destination port to original client port.
	transportSlice := out[ipv6HeaderLen:]
	binary.BigEndian.PutUint16(transportSlice[2:4], m.key.port)

	// Recompute transport checksum from scratch.
	if proto == protoTCP && len(transportSlice) >= 18 {
		binary.BigEndian.PutUint16(transportSlice[16:18], 0)
		csum := computeTransportChecksum(proto, srcIPv6, dstIPv6, transportSlice)
		binary.BigEndian.PutUint16(transportSlice[16:18], csum)
	} else if proto == protoUDP && len(transportSlice) >= 8 {
		binary.BigEndian.PutUint16(transportSlice[6:8], 0)
		csum := computeTransportChecksum(proto, srcIPv6, dstIPv6, transportSlice)
		if csum == 0 {
			csum = 0xffff // IPv6 UDP checksum must not be zero
		}
		binary.BigEndian.PutUint16(transportSlice[6:8], csum)
	}

	n.inside.send(out)
}

func (n *NAT64) handleInboundICMP(icmpData []byte, srcIPv4 netip.Addr, ttl uint8) {
	if len(icmpData) < 8 {
		return
	}

	icmpType := icmpData[0]

	switch icmpType {
	case 0: // Echo Reply → ICMPv6 Echo Reply (type 129)
		n.handleInboundEchoReply(icmpData, srcIPv4, ttl)
	case 3: // Destination Unreachable → mapped per RFC 6145 §4.2
		v6Type, v6Code := icmpv4ToV6DestUnreach(icmpData[1])
		if v6Type != 0 {
			n.handleInboundICMPError(icmpData, srcIPv4, ttl, v6Type, v6Code)
		}
	case 11: // Time Exceeded → ICMPv6 type 3
		n.handleInboundICMPError(icmpData, srcIPv4, ttl, 3, icmpData[1])
	}
}

// icmpv4ToV6DestUnreach maps ICMPv4 Destination Unreachable codes to ICMPv6
// type and code per RFC 6145 §4.2. Returns (0, 0) if the code should be dropped.
func icmpv4ToV6DestUnreach(code uint8) (icmpv6Type, icmpv6Code uint8) {
	switch code {
	case 0: // Net Unreachable → Destination Unreachable, No route
		return 1, 0
	case 1: // Host Unreachable → Destination Unreachable, No route
		return 1, 0
	case 2: // Protocol Unreachable → Parameter Problem, Unrecognized Next Header (RFC 6145 §4.2)
		return 4, 1
	case 3: // Port Unreachable → Destination Unreachable, Port unreachable
		return 1, 4
	case 4: // Fragmentation Needed → Packet Too Big (type 2, code 0; handled separately)
		return 0, 0
	case 5: // Source Route Failed → Destination Unreachable, Source address failed
		return 1, 5
	case 6, 7: // Destination network/host unknown → Destination Unreachable, No route
		return 1, 0
	case 9, 10: // Administratively prohibited → Destination Unreachable, Administratively prohibited
		return 1, 1
	case 13: // Communication Administratively Prohibited
		return 1, 1
	default:
		return 0, 0
	}
}

func (n *NAT64) handleInboundEchoReply(icmpData []byte, srcIPv4 netip.Addr, ttl uint8) {
	id := binary.BigEndian.Uint16(icmpData[4:6])

	rk := nat64RevKey{proto: protoICMP, port: id}
	n.mu.Lock()
	m := n.reverse[rk]
	if m != nil {
		m.lastActive = time.Now()
	}
	n.mu.Unlock()
	if m == nil {
		return
	}

	srcIPv6 := ipv4ToMapped(srcIPv4)
	dstIPv6 := m.key.ip

	// Build ICMPv6 Echo Reply.
	outLen := ipv6HeaderLen + len(icmpData)
	out := make(pktkit.Packet, outLen)

	// IPv6 header.
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(len(icmpData)))
	out[6] = protoICMPv6
	out[7] = ttl
	srcV6 := srcIPv6.As16()
	dstV6 := dstIPv6.As16()
	copy(out[8:24], srcV6[:])
	copy(out[24:40], dstV6[:])

	// Copy ICMP data and translate.
	copy(out[ipv6HeaderLen:], icmpData)
	icmpOut := out[ipv6HeaderLen:]
	icmpOut[0] = 129 // ICMPv6 Echo Reply
	icmpOut[1] = 0
	binary.BigEndian.PutUint16(icmpOut[4:6], m.key.port) // restore original identifier

	// ICMPv6 checksum includes pseudo-header.
	binary.BigEndian.PutUint16(icmpOut[2:4], 0)
	binary.BigEndian.PutUint16(icmpOut[2:4], computeICMPv6Checksum(srcIPv6, dstIPv6, icmpOut))

	n.inside.send(out)
}

func (n *NAT64) handleInboundICMPError(icmpData []byte, srcIPv4 netip.Addr, ttl uint8, icmpv6Type, icmpv6Code uint8) {
	// ICMP error payload contains the original packet header starting at byte 8.
	if len(icmpData) < 8+ipv4MinHeader {
		return
	}
	embOff := 8
	embIHL := int(icmpData[embOff]&0x0F) * 4
	if embIHL < ipv4MinHeader || len(icmpData) < embOff+embIHL+4 {
		return
	}

	embProto := icmpData[embOff+9]
	var embPort uint16
	switch embProto {
	case protoTCP, protoUDP:
		// Source port in the embedded original packet was our mapped port.
		embPort = binary.BigEndian.Uint16(icmpData[embOff+embIHL : embOff+embIHL+2])
	case protoICMP:
		if len(icmpData) < embOff+embIHL+6 {
			return
		}
		embPort = binary.BigEndian.Uint16(icmpData[embOff+embIHL+4 : embOff+embIHL+6])
		// Change embedded protocol to ICMPv6.
		embProto = protoICMP // for lookup purposes, ICMP mappings use protoICMP
	default:
		return
	}

	rk := nat64RevKey{proto: embProto, port: embPort}
	n.mu.Lock()
	m := n.reverse[rk]
	if m != nil {
		m.lastActive = time.Now()
	}
	n.mu.Unlock()
	if m == nil {
		return
	}

	srcIPv6 := ipv4ToMapped(srcIPv4)
	dstIPv6 := m.key.ip

	// Build the embedded IPv6 header from the embedded IPv4 header.
	// We only include the embedded IPv6 header + first 8 bytes of transport
	// (enough for ICMP error processing on the receiving end).
	embTransportLen := len(icmpData) - embOff - embIHL
	if embTransportLen < 0 {
		embTransportLen = 0
	}

	embIPv6Len := ipv6HeaderLen + embTransportLen
	// ICMPv6 error: type(1) + code(1) + checksum(2) + unused(4) + embedded packet
	icmpv6Len := 8 + embIPv6Len

	outLen := ipv6HeaderLen + icmpv6Len
	out := make(pktkit.Packet, outLen)

	// Outer IPv6 header.
	out[0] = 0x60
	binary.BigEndian.PutUint16(out[4:6], uint16(icmpv6Len))
	out[6] = protoICMPv6
	out[7] = ttl
	srcV6 := srcIPv6.As16()
	dstV6 := dstIPv6.As16()
	copy(out[8:24], srcV6[:])
	copy(out[24:40], dstV6[:])

	// ICMPv6 error header.
	icmpOut := out[ipv6HeaderLen:]
	icmpOut[0] = icmpv6Type
	icmpOut[1] = icmpv6Code
	// icmpOut[2:4] = checksum (computed below)
	// icmpOut[4:8] = unused/zero

	// Embedded IPv6 header (translated from embedded IPv4).
	emb := icmpOut[8:]
	emb[0] = 0x60 // version=6
	binary.BigEndian.PutUint16(emb[4:6], uint16(embTransportLen))
	embNextHeader := icmpData[embOff+9]
	if embNextHeader == protoICMP {
		embNextHeader = protoICMPv6
	}
	emb[6] = embNextHeader
	emb[7] = icmpData[embOff+8] // original TTL

	// Embedded src IPv6 = the original inside client (our mapping key).
	origSrcV6 := dstIPv6.As16() // original sender was the inside client
	copy(emb[8:24], origSrcV6[:])
	// Embedded dst IPv6 = ::ffff: + embedded original dst IPv4.
	embDstIPv4 := netip.AddrFrom4([4]byte(icmpData[embOff+16 : embOff+20]))
	embDstIPv6 := ipv4ToMapped(embDstIPv4)
	embDstV6 := embDstIPv6.As16()
	copy(emb[24:40], embDstV6[:])

	// Copy embedded transport data.
	if embTransportLen > 0 {
		copy(emb[ipv6HeaderLen:], icmpData[embOff+embIHL:embOff+embIHL+embTransportLen])
		// Restore original source port in embedded transport.
		embTransport := emb[ipv6HeaderLen:]
		switch icmpData[embOff+9] {
		case protoTCP, protoUDP:
			if len(embTransport) >= 2 {
				binary.BigEndian.PutUint16(embTransport[0:2], m.key.port)
			}
		case protoICMP:
			if len(embTransport) >= 6 {
				embTransport[0] = 128 // translate embedded ICMP Echo to ICMPv6
				binary.BigEndian.PutUint16(embTransport[4:6], m.key.port)
			}
		}
	}

	// Compute ICMPv6 checksum (includes pseudo-header).
	binary.BigEndian.PutUint16(icmpOut[2:4], 0)
	binary.BigEndian.PutUint16(icmpOut[2:4], computeICMPv6Checksum(srcIPv6, dstIPv6, icmpOut))

	n.inside.send(out)
}

// --- Mapping management ---

func (n *NAT64) getOrCreateMapping(k nat64Key) *nat64Mapping {
	n.mu.Lock()
	defer n.mu.Unlock()

	if m, ok := n.mappings[k]; ok {
		m.lastActive = time.Now()
		return m
	}

	port := n.allocPort()
	if port == 0 {
		return nil
	}

	m := &nat64Mapping{
		key:         k,
		outsidePort: port,
		lastActive:  time.Now(),
	}
	n.mappings[k] = m
	n.reverse[nat64RevKey{proto: k.proto, port: port}] = m
	return m
}

func (n *NAT64) allocPort() uint16 {
	start := n.nextPort
	for {
		p := n.nextPort
		n.nextPort++
		if n.nextPort > natPortMax {
			n.nextPort = natPortMin
		}
		inUse := false
		for _, proto := range []uint8{protoTCP, protoUDP, protoICMP} {
			if _, ok := n.reverse[nat64RevKey{proto: proto, port: p}]; ok {
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

func (n *NAT64) maintenance() {
	ticker := time.NewTicker(natCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-n.done:
			return
		case <-ticker.C:
		}
		now := time.Now()
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
			if timeout == 0 || now.Sub(m.lastActive) > timeout {
				delete(n.mappings, k)
				delete(n.reverse, nat64RevKey{proto: k.proto, port: m.outsidePort})
			}
		}
		n.mu.Unlock()
	}
}
