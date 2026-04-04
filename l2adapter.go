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

	arp     *arpTable
	pending *arpPending
	dhcp    *dhcpClient

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
		mac:     mac,
		l3dev:   dev,
		arp:     newARPTable(),
		pending: newARPPending(),
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

// Close stops DHCP and releases resources.
func (a *L2Adapter) Close() error {
	a.dhcp.Stop()
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

		// Intercept DHCP responses (IPv4 UDP port 68)
		if pkt.Version() == 4 && pkt.IPv4Protocol() == ProtocolUDP {
			udpPayload := pkt.IPv4Payload()
			if len(udpPayload) >= 8 {
				dstPort := binary.BigEndian.Uint16(udpPayload[2:4])
				if dstPort == 68 {
					a.dhcp.HandlePacket(udpPayload[8:])
					return nil
				}
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
			// IPv6 unicast needs NDP, not implemented yet.
			return
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
