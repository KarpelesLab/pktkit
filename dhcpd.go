package pktkit

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// DHCPServerConfig configures a DHCP server.
type DHCPServerConfig struct {
	// ServerIP is the server's own IP address.
	ServerIP netip.Addr
	// SubnetMask is the subnet mask to advertise.
	SubnetMask net.IPMask
	// RangeStart is the first IP in the leasable pool.
	RangeStart netip.Addr
	// RangeEnd is the last IP in the leasable pool (inclusive).
	RangeEnd netip.Addr
	// Router is the default gateway to advertise.
	Router netip.Addr
	// DNS is the list of DNS servers to advertise.
	DNS []netip.Addr
	// LeaseTime is the lease duration. Defaults to 1 hour if zero.
	LeaseTime time.Duration
	// MAC is the server's hardware address. Generated if nil.
	MAC net.HardwareAddr
}

type dhcpLease struct {
	ip     netip.Addr
	mac    [6]byte
	expiry time.Time
}

const maxDHCPLeases = 1024

// DHCPServer is an L2 device that serves DHCP leases on an Ethernet network.
type DHCPServer struct {
	cfg     DHCPServerConfig
	mac     net.HardwareAddr
	handler atomic.Pointer[func(Frame) error]

	mu       sync.Mutex
	leases   map[[6]byte]*dhcpLease   // keyed by client MAC
	declined map[netip.Addr]time.Time // IPs declined by clients
}

// NewDHCPServer creates a new DHCP server with the given configuration.
func NewDHCPServer(cfg DHCPServerConfig) *DHCPServer {
	if cfg.LeaseTime == 0 {
		cfg.LeaseTime = time.Hour
	}
	mac := cfg.MAC
	if mac == nil {
		mac = net.HardwareAddr{0x02, 0xDD, 0xCC, 0x00, 0x00, 0x01}
	}
	return &DHCPServer{
		cfg:      cfg,
		mac:      mac,
		leases:   make(map[[6]byte]*dhcpLease),
		declined: make(map[netip.Addr]time.Time),
	}
}

// --- L2Device implementation ---

func (s *DHCPServer) SetHandler(h func(Frame) error) {
	s.handler.Store(&h)
}

func (s *DHCPServer) Send(f Frame) error {
	if !f.IsValid() || f.EtherType() != EtherTypeIPv4 {
		return nil
	}
	payload := f.Payload()
	if len(payload) < 28 { // min IPv4 + UDP
		return nil
	}
	// Check IPv4 protocol = UDP
	if payload[9] != byte(ProtocolUDP) {
		return nil
	}
	ihl := int(payload[0]&0x0F) * 4
	if len(payload) < ihl+8 {
		return nil
	}
	udp := payload[ihl:]
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if dstPort != 67 {
		return nil
	}
	// Extract DHCP payload (after UDP header)
	udpLen := binary.BigEndian.Uint16(udp[4:6])
	if int(udpLen) < 8 || len(udp) < int(udpLen) {
		return nil
	}
	dhcpPayload := udp[8:udpLen]
	s.handleDHCP(dhcpPayload)
	return nil
}

func (s *DHCPServer) HWAddr() net.HardwareAddr { return s.mac }
func (s *DHCPServer) Close() error             { return nil }

// --- DHCP handling ---

func (s *DHCPServer) handleDHCP(msg []byte) {
	if len(msg) < 240 {
		return
	}
	if msg[0] != 1 { // must be BOOTREQUEST
		return
	}

	xid := binary.BigEndian.Uint32(msg[4:8])
	var chaddr [6]byte
	copy(chaddr[:], msg[28:34])

	// Verify magic cookie
	if msg[236] != 99 || msg[237] != 130 || msg[238] != 83 || msg[239] != 99 {
		return
	}

	// Parse options
	var msgType byte
	var requestedIP netip.Addr
	opts := msg[240:]
	for len(opts) > 0 {
		if opts[0] == dhcpOptEnd {
			break
		}
		if opts[0] == 0 {
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
		case dhcpOptRequestedIP:
			if length == 4 {
				requestedIP = netip.AddrFrom4([4]byte(data[:4]))
			}
		}
		opts = opts[2+length:]
	}

	switch msgType {
	case dhcpDiscover:
		ip := s.allocate(chaddr)
		if !ip.IsValid() {
			return
		}
		s.sendReply(dhcpOffer, xid, chaddr, ip)
	case dhcpRequest:
		ip := s.confirm(chaddr, requestedIP)
		if !ip.IsValid() {
			return
		}
		s.sendReply(dhcpAck, xid, chaddr, ip)
	case 7: // RELEASE
		s.release(chaddr)
	case 4: // DECLINE
		s.decline(chaddr, requestedIP)
	case 8: // INFORM
		// Respond with ACK containing config but no IP assignment.
		s.sendReply(dhcpAck, xid, chaddr, netip.Addr{})
	}
}

// allocate finds or assigns an IP for the given MAC.
func (s *DHCPServer) allocate(mac [6]byte) netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Existing lease?
	if l, ok := s.leases[mac]; ok {
		l.expiry = time.Now().Add(s.cfg.LeaseTime)
		return l.ip
	}

	// Find a free IP in the range
	now := time.Now()
	assigned := make(map[netip.Addr]bool)
	for _, l := range s.leases {
		if now.Before(l.expiry) {
			assigned[l.ip] = true
		}
	}

	if len(s.leases) >= maxDHCPLeases {
		return netip.Addr{} // lease table full
	}

	for ip := s.cfg.RangeStart; ip.Compare(s.cfg.RangeEnd) <= 0; ip = ip.Next() {
		if assigned[ip] {
			continue
		}
		// Skip declined IPs that haven't expired yet.
		if exp, declined := s.declined[ip]; declined && now.Before(exp) {
			continue
		}
		delete(s.declined, ip) // clean up expired decline
		s.leases[mac] = &dhcpLease{ip: ip, mac: mac, expiry: now.Add(s.cfg.LeaseTime)}
		return ip
	}
	return netip.Addr{} // pool exhausted
}

// confirm validates a REQUEST for the given MAC and IP.
func (s *DHCPServer) confirm(mac [6]byte, requested netip.Addr) netip.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()

	l, ok := s.leases[mac]
	if !ok {
		// No existing lease — try to grant the requested IP if it's valid and in range.
		if len(s.leases) >= maxDHCPLeases {
			return netip.Addr{} // lease table full
		}
		if !requested.IsValid() {
			return netip.Addr{}
		}
		if requested == s.cfg.ServerIP {
			return netip.Addr{} // can't lease the server's own IP
		}
		if requested.Compare(s.cfg.RangeStart) < 0 || requested.Compare(s.cfg.RangeEnd) > 0 {
			return netip.Addr{} // outside the configured pool
		}
		// Check for conflicts with existing leases.
		now := time.Now()
		for _, other := range s.leases {
			if other.ip == requested && now.Before(other.expiry) {
				return netip.Addr{} // already leased to another client
			}
		}
		if exp, declined := s.declined[requested]; declined && now.Before(exp) {
			return netip.Addr{} // currently declined
		}
		s.leases[mac] = &dhcpLease{ip: requested, mac: mac, expiry: now.Add(s.cfg.LeaseTime)}
		return requested
	}
	if requested.IsValid() && requested != l.ip {
		return netip.Addr{} // mismatch
	}
	l.expiry = time.Now().Add(s.cfg.LeaseTime)
	return l.ip
}

// release frees the lease for the given client MAC.
func (s *DHCPServer) release(mac [6]byte) {
	s.mu.Lock()
	delete(s.leases, mac)
	s.mu.Unlock()
}

// decline marks an IP as unusable for a period (client detected a conflict).
func (s *DHCPServer) decline(mac [6]byte, ip netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Remove the lease.
	delete(s.leases, mac)
	// Mark the IP as declined for the lease duration.
	if ip.IsValid() {
		s.declined[ip] = time.Now().Add(s.cfg.LeaseTime)
	}
}

// sendReply constructs and sends a DHCP OFFER or ACK.
func (s *DHCPServer) sendReply(msgType byte, xid uint32, chaddr [6]byte, yiaddr netip.Addr) {
	// BOOTP reply — allocate enough for header + options including DNS servers.
	// 240 (BOOTP header + magic cookie) + 3 (msg type) + 6 (subnet) + 6 (router)
	// + 2 + 4*len(DNS) + 6 (lease time) + 6 (server ID) + 1 (end) = 270 + 4*len(DNS)
	bufSize := 270 + len(s.cfg.DNS)*4
	if bufSize < 300 {
		bufSize = 300 // BOOTP minimum
	}
	buf := make([]byte, bufSize)
	buf[0] = 2 // op: BOOTREPLY
	buf[1] = 1 // htype: Ethernet
	buf[2] = 6 // hlen
	binary.BigEndian.PutUint32(buf[4:8], xid)
	// yiaddr (zero for INFORM responses)
	if yiaddr.IsValid() {
		ya := yiaddr.As4()
		copy(buf[16:20], ya[:])
	}
	// siaddr (server IP)
	sa := s.cfg.ServerIP.As4()
	copy(buf[20:24], sa[:])
	// chaddr
	copy(buf[28:34], chaddr[:])

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

	// Subnet mask
	if s.cfg.SubnetMask != nil {
		buf[off] = dhcpOptSubnetMask
		buf[off+1] = 4
		copy(buf[off+2:off+6], s.cfg.SubnetMask)
		off += 6
	}

	// Router
	if s.cfg.Router.IsValid() {
		buf[off] = dhcpOptRouter
		buf[off+1] = 4
		r := s.cfg.Router.As4()
		copy(buf[off+2:off+6], r[:])
		off += 6
	}

	// DNS servers
	if len(s.cfg.DNS) > 0 {
		buf[off] = dhcpOptDNS
		buf[off+1] = byte(len(s.cfg.DNS) * 4)
		off += 2
		for _, dns := range s.cfg.DNS {
			d := dns.As4()
			copy(buf[off:off+4], d[:])
			off += 4
		}
	}

	// Lease time and server identifier — omit for INFORM responses (no IP assigned).
	if yiaddr.IsValid() {
		buf[off] = dhcpOptLeaseTime
		buf[off+1] = 4
		binary.BigEndian.PutUint32(buf[off+2:off+6], uint32(s.cfg.LeaseTime.Seconds()))
		off += 6

		buf[off] = dhcpOptServerID
		buf[off+1] = 4
		copy(buf[off+2:off+6], sa[:])
		off += 6
	}

	buf[off] = dhcpOptEnd
	off++

	dhcpPayload := buf[:off]

	// Wrap in UDP
	udpLen := 8 + len(dhcpPayload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 67) // src port
	binary.BigEndian.PutUint16(udp[2:4], 68) // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	// checksum = 0 (optional for IPv4 UDP)
	copy(udp[8:], dhcpPayload)

	// Wrap in IPv4
	ipLen := 20 + udpLen
	ip := make([]byte, ipLen)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = byte(ProtocolUDP)
	copy(ip[12:16], sa[:])
	// dst = 255.255.255.255
	ip[16] = 0xff
	ip[17] = 0xff
	ip[18] = 0xff
	ip[19] = 0xff
	binary.BigEndian.PutUint16(ip[10:12], Checksum(ip[:20]))
	copy(ip[20:], udp)

	// Wrap in Ethernet
	dstMAC := net.HardwareAddr(chaddr[:])
	frame := NewFrame(dstMAC, s.mac, EtherTypeIPv4, ip)

	if h := s.handler.Load(); h != nil {
		(*h)(frame)
	}
}
