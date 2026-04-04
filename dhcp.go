package pktkit

import (
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DHCP message types (option 53)
const (
	dhcpDiscover = 1
	dhcpOffer    = 2
	dhcpRequest  = 3
	dhcpAck      = 5
	dhcpNak      = 6
)

// DHCP option codes
const (
	dhcpOptSubnetMask   = 1
	dhcpOptRouter       = 3
	dhcpOptDNS          = 6
	dhcpOptRequestedIP  = 50
	dhcpOptLeaseTime    = 51
	dhcpOptMessageType  = 53
	dhcpOptServerID     = 54
	dhcpOptParamRequest = 55
	dhcpOptEnd          = 255
)

type dhcpState int

const (
	dhcpInit dhcpState = iota
	dhcpSelecting
	dhcpRequesting
	dhcpBound
	dhcpRenewing
)

// dhcpClient implements a minimal DHCP client state machine.
type dhcpClient struct {
	adapter *L2Adapter

	mu        sync.Mutex
	state     dhcpState
	xid       uint32
	offeredIP netip.Addr
	serverIP  netip.Addr
	leaseTime time.Duration
	timer     *time.Timer
}

func newDHCPClient(a *L2Adapter) *dhcpClient {
	return &dhcpClient{adapter: a}
}

// Start begins the DHCP discovery process.
func (d *dhcpClient) Start() {
	d.mu.Lock()
	d.xid = rand.Uint32()
	d.state = dhcpSelecting
	d.mu.Unlock()
	d.sendDiscover()
}

// Stop cancels any running DHCP operations.
func (d *dhcpClient) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.state = dhcpInit
}

// HandlePacket processes an incoming DHCP response (UDP payload on port 68).
func (d *dhcpClient) HandlePacket(udpPayload []byte) {
	if len(udpPayload) < 240 {
		return
	}

	// Verify it's a BOOTREPLY (op=2) and matches our xid
	if udpPayload[0] != 2 {
		return
	}

	d.mu.Lock()
	// Lock is released before sending to avoid deadlock with synchronous callbacks.

	xid := binary.BigEndian.Uint32(udpPayload[4:8])
	if xid != d.xid {
		d.mu.Unlock()
		return
	}

	// yiaddr: offered IP
	yiaddr := netip.AddrFrom4([4]byte(udpPayload[16:20]))

	// Parse options (start at offset 240, after magic cookie)
	if len(udpPayload) < 244 {
		d.mu.Unlock()
		return
	}
	// Verify magic cookie
	if udpPayload[236] != 99 || udpPayload[237] != 130 || udpPayload[238] != 83 || udpPayload[239] != 99 {
		d.mu.Unlock()
		return
	}

	var msgType byte
	var subnetMask netip.Addr
	var serverID netip.Addr
	var router netip.Addr
	var leaseTime uint32

	opts := udpPayload[240:]
	for len(opts) > 0 {
		if opts[0] == dhcpOptEnd {
			break
		}
		if opts[0] == 0 { // pad
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 {
			break
		}
		code := opts[0]
		length := int(opts[1])
		if len(opts) < 2+length {
			break
		}
		data := opts[2 : 2+length]

		switch code {
		case dhcpOptMessageType:
			if length >= 1 {
				msgType = data[0]
			}
		case dhcpOptSubnetMask:
			if length == 4 {
				subnetMask = netip.AddrFrom4([4]byte(data[:4]))
			}
		case dhcpOptServerID:
			if length == 4 {
				serverID = netip.AddrFrom4([4]byte(data[:4]))
			}
		case dhcpOptRouter:
			if length >= 4 {
				router = netip.AddrFrom4([4]byte(data[:4]))
			}
		case dhcpOptLeaseTime:
			if length == 4 {
				leaseTime = binary.BigEndian.Uint32(data[:4])
			}
		}

		opts = opts[2+length:]
	}

	// Determine action under lock, then release before sending.
	var action int // 0=none, 1=sendRequest, 2=sendDiscover
	switch d.state {
	case dhcpSelecting:
		if msgType == dhcpOffer {
			d.offeredIP = yiaddr
			d.serverIP = serverID
			d.state = dhcpRequesting
			action = 1
		}

	case dhcpRequesting, dhcpRenewing:
		switch msgType {
		case dhcpAck:
			bits := 24
			if subnetMask.IsValid() {
				m := subnetMask.As4()
				bits = maskBits(m)
			}
			prefix := netip.PrefixFrom(yiaddr, bits)
			d.adapter.l3dev.SetAddr(prefix)
			if router.IsValid() {
				d.adapter.SetGateway(router)
			}
			d.state = dhcpBound
			if leaseTime > 0 {
				d.leaseTime = time.Duration(leaseTime) * time.Second
				if d.timer != nil {
					d.timer.Stop()
				}
				d.timer = time.AfterFunc(d.leaseTime/2, func() {
					d.mu.Lock()
					if d.state == dhcpBound {
						d.state = dhcpRenewing
					}
					d.mu.Unlock()
					d.sendRequest()
				})
			}
		case dhcpNak:
			d.state = dhcpSelecting
			d.xid = rand.Uint32()
			action = 2
		}
	}
	d.mu.Unlock()

	switch action {
	case 1:
		d.sendRequest()
	case 2:
		d.sendDiscover()
	}
}

func (d *dhcpClient) sendDiscover() {
	payload := d.buildDHCPMessage(dhcpDiscover, netip.Addr{}, netip.Addr{})
	d.sendDHCPFrame(payload)
}

func (d *dhcpClient) sendRequest() {
	payload := d.buildDHCPMessage(dhcpRequest, d.offeredIP, d.serverIP)
	d.sendDHCPFrame(payload)
}

// buildDHCPMessage constructs a DHCP/BOOTP message payload.
func (d *dhcpClient) buildDHCPMessage(msgType byte, requestedIP, serverID netip.Addr) []byte {
	// BOOTP header: 236 bytes + 4 byte magic cookie + options
	buf := make([]byte, 300)
	buf[0] = 1 // op: BOOTREQUEST
	buf[1] = 1 // htype: Ethernet
	buf[2] = 6 // hlen
	buf[3] = 0 // hops
	binary.BigEndian.PutUint32(buf[4:8], d.xid)
	// secs, flags = 0
	// ciaddr = 0
	// yiaddr = 0
	// siaddr = 0
	// giaddr = 0
	copy(buf[28:34], d.adapter.mac) // chaddr

	// Magic cookie
	buf[236] = 99
	buf[237] = 130
	buf[238] = 83
	buf[239] = 99

	// Options
	off := 240

	// Message type
	buf[off] = dhcpOptMessageType
	buf[off+1] = 1
	buf[off+2] = msgType
	off += 3

	// Requested IP (for REQUEST)
	if requestedIP.IsValid() {
		buf[off] = dhcpOptRequestedIP
		buf[off+1] = 4
		ip4 := requestedIP.As4()
		copy(buf[off+2:off+6], ip4[:])
		off += 6
	}

	// Server ID (for REQUEST)
	if serverID.IsValid() {
		buf[off] = dhcpOptServerID
		buf[off+1] = 4
		ip4 := serverID.As4()
		copy(buf[off+2:off+6], ip4[:])
		off += 6
	}

	// Parameter request list
	buf[off] = dhcpOptParamRequest
	buf[off+1] = 3
	buf[off+2] = dhcpOptSubnetMask
	buf[off+3] = dhcpOptRouter
	buf[off+4] = dhcpOptDNS
	off += 5

	buf[off] = dhcpOptEnd
	off++

	return buf[:off]
}

// sendDHCPFrame wraps a DHCP payload in UDP+IPv4+Ethernet and sends it.
func (d *dhcpClient) sendDHCPFrame(dhcpPayload []byte) {
	// UDP header (8 bytes)
	udpLen := 8 + len(dhcpPayload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 68)             // src port
	binary.BigEndian.PutUint16(udp[2:4], 67)             // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen)) // length
	// checksum = 0 (optional for IPv4 UDP)
	copy(udp[8:], dhcpPayload)

	// IPv4 header (20 bytes, no options)
	ipLen := 20 + udpLen
	ip := make([]byte, ipLen)
	ip[0] = 0x45                                       // version=4, IHL=5
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen)) // total length
	ip[8] = 64                                         // TTL
	ip[9] = byte(ProtocolUDP)                          // protocol
	// src = 0.0.0.0, dst = 255.255.255.255
	ip[16] = 0xff
	ip[17] = 0xff
	ip[18] = 0xff
	ip[19] = 0xff
	// Compute IP header checksum
	csum := Checksum(ip[:20])
	binary.BigEndian.PutUint16(ip[10:12], csum)
	copy(ip[20:], udp)

	// Ethernet frame
	frame := NewFrame(broadcastMAC, d.adapter.mac, EtherTypeIPv4, ip)
	d.adapter.sendL2(frame)
}

// maskBits returns the number of leading 1-bits in a 4-byte subnet mask.
func maskBits(mask [4]byte) int {
	m := net.IPv4Mask(mask[0], mask[1], mask[2], mask[3])
	ones, _ := m.Size()
	return ones
}
