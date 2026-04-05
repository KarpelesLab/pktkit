package pktkit

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

const defaultFrameBufSize = 1536 // 14-byte header + 1522-byte payload

// L2Adapter wraps an L3Device and presents it as an L2Device. It handles
// Ethernet framing, ARP resolution, and optionally DHCP for IP acquisition
// on behalf of the underlying L3 device.
//
// Usage:
//
//	l3dev := NewPipeL3(netip.MustParsePrefix("10.0.0.2/24"))
//	adapter := NewL2Adapter(l3dev, nil) // random MAC
//	hub.Connect(adapter) // adapter implements L2Device
type L2Adapter struct {
	mac   net.HardwareAddr
	l3dev L3Device

	// Handler set by the L2 network (e.g. hub) to receive frames from us.
	l2handler atomic.Pointer[func(Frame) error]

	gateway atomic.Value // netip.Addr — next-hop for off-subnet destinations

	arp        *arpTable
	ndp        *ndpTable
	pending    *arpPending // shared for ARP and NDP
	ndpPending *arpPending // separate pending queue for NDP
	dhcp       *dhcpClient

	framePool sync.Pool
}

// NewL2Adapter creates an adapter that wraps the given L3Device. If mac is
// nil, a random locally-administered unicast MAC address is generated.
// It wires itself as the L3Device's handler so that outgoing packets are
// automatically framed and sent on the L2 network.
func NewL2Adapter(dev L3Device, mac net.HardwareAddr) *L2Adapter {
	if mac == nil {
		mac = make(net.HardwareAddr, 6)
		rand.Read(mac)
		mac[0] = mac[0]&0xFE | 0x02 // locally administered, unicast
	}
	a := &L2Adapter{
		mac:        mac,
		l3dev:      dev,
		arp:        newARPTable(),
		ndp:        newNDPTable(),
		pending:    newARPPending(),
		ndpPending: newARPPending(),
		framePool: sync.Pool{
			New: func() any {
				buf := make([]byte, defaultFrameBufSize)
				return &buf
			},
		},
	}
	a.dhcp = newDHCPClient(a)

	// When the L3 device produces a packet, wrap it in Ethernet and send.
	dev.SetHandler(func(pkt Packet) error {
		a.handleOutgoingL3Packet(pkt)
		return nil
	})

	return a
}

// --- L2Device implementation ---

// SetHandler is called by the L2 network (e.g. an L2Hub) to receive frames
// produced by this adapter.
func (a *L2Adapter) SetHandler(h func(Frame) error) {
	a.l2handler.Store(&h)
}

// Send delivers a frame from the L2 network to this adapter. The adapter
// filters by destination MAC, handles ARP, intercepts DHCP, and forwards
// IP payloads to the wrapped L3 device.
func (a *L2Adapter) Send(f Frame) error {
	return a.handleIncomingL2Frame(f)
}

// HWAddr returns the adapter's MAC address.
func (a *L2Adapter) HWAddr() net.HardwareAddr {
	return a.mac
}

// Close stops DHCP, pending queue cleanup, and releases resources.
func (a *L2Adapter) Close() error {
	a.dhcp.Stop()
	a.pending.Close()
	a.ndpPending.Close()
	return nil
}

// SetGateway sets the default gateway for off-subnet routing.
// When sending to an IP not covered by the L3 device's prefix, the adapter
// will ARP for the gateway MAC instead of the destination IP directly.
func (a *L2Adapter) SetGateway(gw netip.Addr) {
	a.gateway.Store(gw)
}

// --- DHCP controls ---

// StartDHCP begins DHCP discovery to obtain an IP address for the
// underlying L3 device.
func (a *L2Adapter) StartDHCP() {
	a.dhcp.Start()
}

// StopDHCP cancels any running DHCP operations.
func (a *L2Adapter) StopDHCP() {
	a.dhcp.Stop()
}

// --- Internal ---

// sendL2 sends a frame out to the L2 network via the handler.
func (a *L2Adapter) sendL2(f Frame) {
	if h := a.l2handler.Load(); h != nil {
		(*h)(f)
	}
}

// handleIncomingL2Frame processes a frame received from the L2 network.
func (a *L2Adapter) handleIncomingL2Frame(f Frame) error {
	if !f.IsValid() {
		return nil
	}

	// Filter: only accept frames addressed to us or broadcast/multicast.
	dst := f.DstMAC()
	if !f.IsBroadcast() && !f.IsMulticast() && !macEqual(dst, a.mac) {
		return nil
	}

	switch f.EtherType() {
	case EtherTypeARP:
		a.handleARP(f)
	case EtherTypeIPv4, EtherTypeIPv6:
		payload := f.Payload()
		if len(payload) == 0 {
			return nil
		}
		pkt := Packet(payload)
		if !pkt.IsValid() {
			return nil
		}

		// Intercept DHCP responses (IPv4 UDP port 68) only when DHCP is active.
		if pkt.Version() == 4 && pkt.IPv4Protocol() == ProtocolUDP {
			udpPayload := pkt.IPv4Payload()
			if len(udpPayload) >= 8 {
				dstPort := binary.BigEndian.Uint16(udpPayload[2:4])
				if dstPort == 68 && a.dhcp.isActive() {
					a.dhcp.HandlePacket(udpPayload[8:])
					return nil
				}
			}
		}

		// Intercept ICMPv6 NDP messages.
		// RFC 4861 §6.1.1: NDP messages MUST have hop limit 255
		// to prevent off-link spoofing.
		if pkt.Version() == 6 && pkt.IPv6NextHeader() == ProtocolICMPv6 && pkt.IPv6HopLimit() == 255 {
			if a.handleNDP(pkt) {
				return nil // consumed by NDP
			}
		}

		// Forward to the wrapped L3 device.
		a.l3dev.Send(pkt)
	}

	return nil
}

// handleOutgoingL3Packet wraps a packet from the L3 device in an Ethernet
// frame and sends it on the L2 network.
func (a *L2Adapter) handleOutgoingL3Packet(pkt Packet) {
	if !pkt.IsValid() {
		return
	}

	var dstMAC net.HardwareAddr
	var etherType EtherType

	switch pkt.Version() {
	case 4:
		etherType = EtherTypeIPv4
		if pkt.IsBroadcast() {
			dstMAC = broadcastMAC
		} else if pkt.IsMulticast() {
			dst := pkt.IPv4DstAddr().As4()
			dstMAC = net.HardwareAddr{0x01, 0x00, 0x5E, dst[1] & 0x7F, dst[2], dst[3]}
		} else {
			// Determine ARP target: use gateway for off-subnet destinations.
			arpTarget := pkt.IPv4DstAddr()
			prefix := a.l3dev.Addr()
			if prefix.IsValid() && !prefix.Contains(arpTarget) {
				if gw, ok := a.gateway.Load().(netip.Addr); ok && gw.IsValid() {
					arpTarget = gw
				}
			}
			mac, ok := a.arp.Lookup(arpTarget)
			if !ok {
				sendReq := a.pending.Enqueue(arpTarget, pkt)
				if sendReq {
					a.sendARPRequest(arpTarget)
				}
				return
			}
			dstMAC = mac
		}
	case 6:
		etherType = EtherTypeIPv6
		if pkt.IsMulticast() {
			dst := pkt.IPv6DstAddr().As16()
			dstMAC = net.HardwareAddr{0x33, 0x33, dst[12], dst[13], dst[14], dst[15]}
		} else {
			// IPv6 unicast: resolve via NDP (use gateway for off-link).
			ndpTarget := pkt.IPv6DstAddr()
			prefix := a.l3dev.Addr()
			if prefix.IsValid() && prefix.Addr().Is6() && !prefix.Contains(ndpTarget) {
				if gw, ok := a.gateway.Load().(netip.Addr); ok && gw.IsValid() && gw.Is6() {
					ndpTarget = gw
				}
			}
			mac, ok := a.ndp.Lookup(ndpTarget)
			if !ok {
				sendReq := a.ndpPending.Enqueue(ndpTarget, pkt)
				if sendReq {
					a.sendNeighborSolicitation(ndpTarget)
				}
				return
			}
			dstMAC = mac
		}
	default:
		return
	}

	// Build Ethernet frame from pool buffer.
	frameLen := 14 + len(pkt)
	bufp := a.framePool.Get().(*[]byte)
	buf := *bufp
	if len(buf) < frameLen {
		buf = make([]byte, frameLen)
	}
	buf = buf[:frameLen]

	copy(buf[0:6], dstMAC)
	copy(buf[6:12], a.mac)
	binary.BigEndian.PutUint16(buf[12:14], uint16(etherType))
	copy(buf[14:], pkt)

	a.sendL2(Frame(buf))

	// Return buffer to pool.
	*bufp = buf[:cap(buf)]
	a.framePool.Put(bufp)
}

// handleARP processes an incoming ARP frame.
func (a *L2Adapter) handleARP(f Frame) {
	op, senderMAC, senderIP, _, targetIP, ok := parseARP(f.Payload())
	if !ok {
		return
	}

	// Learn the sender.
	a.arp.Set(senderIP, senderMAC, arpDefaultTTL)

	// Drain any pending packets for this sender IP.
	if pending := a.pending.Drain(senderIP); len(pending) > 0 {
		for _, pkt := range pending {
			a.handleOutgoingL3Packet(pkt)
		}
	}

	// Respond to requests for our IP.
	ourAddr := a.l3dev.Addr().Addr()
	if op == arpOpRequest && targetIP == ourAddr {
		a.sendARPReply(senderMAC, senderIP)
	}
}

// sendARPRequest sends an ARP request for the given IP.
func (a *L2Adapter) sendARPRequest(targetIP netip.Addr) {
	ourAddr := a.l3dev.Addr().Addr()
	payload := buildARPPacket(arpOpRequest, a.mac, ourAddr, net.HardwareAddr{0, 0, 0, 0, 0, 0}, targetIP)
	frame := NewFrame(broadcastMAC, a.mac, EtherTypeARP, payload)
	a.sendL2(frame)
}

// sendARPReply sends an ARP reply to the given destination.
func (a *L2Adapter) sendARPReply(dstMAC net.HardwareAddr, dstIP netip.Addr) {
	ourAddr := a.l3dev.Addr().Addr()
	payload := buildARPPacket(arpOpReply, a.mac, ourAddr, dstMAC, dstIP)
	frame := NewFrame(dstMAC, a.mac, EtherTypeARP, payload)
	a.sendL2(frame)
}

// --- NDP handling ---

// handleNDP processes incoming ICMPv6 NDP messages. Returns true if consumed.
func (a *L2Adapter) handleNDP(pkt Packet) bool {
	icmp := pkt.IPv6Payload()
	if len(icmp) < 4 {
		return false
	}
	srcAddr := pkt.IPv6SrcAddr()

	switch icmp[0] {
	case icmpv6NeighborSolicitation:
		if len(icmp) < 24 {
			return false
		}
		targetAddr := netip.AddrFrom16([16]byte(icmp[8:24]))
		// Learn sender if source link-layer option present.
		// RFC 4861 §7.1.1: if source is unspecified (DAD), do NOT learn.
		if srcMAC := parseNDPOption(icmp[24:], ndpOptSourceLinkAddr); srcMAC != nil && srcAddr.IsValid() && !srcAddr.IsUnspecified() {
			a.ndp.Set(srcAddr, srcMAC, ndpDefaultTTL)
		}
		// Respond if targeted at our address.
		llAddr := linkLocalFromMAC(a.mac)
		devAddr := a.l3dev.Addr().Addr()
		if targetAddr == llAddr || (devAddr.Is6() && targetAddr == devAddr) {
			if srcAddr.IsUnspecified() {
				// DAD NS: respond to all-nodes multicast, solicited=false (RFC 4861 §7.2.4).
				allNodes := netip.MustParseAddr("ff02::1")
				a.sendNeighborAdvertisement(allNodes, targetAddr)
			} else {
				a.sendNeighborAdvertisement(srcAddr, targetAddr)
			}
		}
		return true

	case icmpv6NeighborAdvertisement:
		if len(icmp) < 24 {
			return false
		}
		targetAddr := netip.AddrFrom16([16]byte(icmp[8:24]))
		// Learn from target link-layer option
		if targetMAC := parseNDPOption(icmp[24:], ndpOptTargetLinkAddr); targetMAC != nil {
			a.ndp.Set(targetAddr, targetMAC, ndpDefaultTTL)
			// Drain pending packets
			if pending := a.ndpPending.Drain(targetAddr); len(pending) > 0 {
				for _, p := range pending {
					a.handleOutgoingL3Packet(p)
				}
			}
		}
		return true

	case icmpv6RouterSolicitation, icmpv6RouterAdvertisement:
		// Pass through to L3 device (not consumed here)
		return false
	}
	return false
}

// sendNeighborSolicitation sends an ICMPv6 NS for the given target address.
func (a *L2Adapter) sendNeighborSolicitation(target netip.Addr) {
	srcAddr := linkLocalFromMAC(a.mac)
	dstAddr := solicitedNodeMulticast(target)
	dstMAC := solicitedNodeMAC(target)

	icmpPayload := buildNeighborSolicitation(a.mac, target)
	ipPkt := wrapICMPv6(srcAddr, dstAddr, icmpPayload)
	frame := NewFrame(dstMAC, a.mac, EtherTypeIPv6, ipPkt)
	a.sendL2(frame)
}

// sendNeighborAdvertisement sends an ICMPv6 NA in response to an NS.
func (a *L2Adapter) sendNeighborAdvertisement(dstAddr netip.Addr, targetAddr netip.Addr) {
	srcAddr := targetAddr // source is the address being advertised
	var dstMAC net.HardwareAddr
	if mac, ok := a.ndp.Lookup(dstAddr); ok {
		dstMAC = mac
	} else {
		// Multicast fallback if we don't know the requester's MAC
		d := dstAddr.As16()
		dstMAC = net.HardwareAddr{0x33, 0x33, d[12], d[13], d[14], d[15]}
	}

	// RFC 4861 §7.2.4: solicited flag MUST NOT be set when responding to
	// a DAD NS (destination is multicast, not unicast).
	solicited := !dstAddr.IsMulticast()
	icmpPayload := buildNeighborAdvertisement(a.mac, targetAddr, solicited)
	ipPkt := wrapICMPv6(srcAddr, dstAddr, icmpPayload)
	frame := NewFrame(dstMAC, a.mac, EtherTypeIPv6, ipPkt)
	a.sendL2(frame)
}

// macEqual compares two MAC addresses.
func macEqual(a, b net.HardwareAddr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
