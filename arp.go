package pktkit

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"
)

const (
	arpOpRequest = 1
	arpOpReply   = 2

	arpDefaultTTL     = 5 * time.Minute
	arpPendingMaxPkts = 16
)

var broadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type arpEntry struct {
	mac     net.HardwareAddr
	expires time.Time
}

// arpTable is a thread-safe ARP cache mapping IPv4 addresses to MAC addresses.
type arpTable struct {
	mu      sync.RWMutex
	entries map[netip.Addr]arpEntry
}

func newARPTable() *arpTable {
	return &arpTable{entries: make(map[netip.Addr]arpEntry)}
}

// Lookup returns the MAC for the given IP, or false if not found or expired.
func (t *arpTable) Lookup(ip netip.Addr) (net.HardwareAddr, bool) {
	t.mu.RLock()
	e, ok := t.entries[ip]
	t.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expires) {
		t.mu.Lock()
		delete(t.entries, ip)
		t.mu.Unlock()
		return nil, false
	}
	return e.mac, true
}

// Set stores a MAC for the given IP with the specified TTL.
func (t *arpTable) Set(ip netip.Addr, mac net.HardwareAddr, ttl time.Duration) {
	t.mu.Lock()
	t.entries[ip] = arpEntry{mac: mac, expires: time.Now().Add(ttl)}
	t.mu.Unlock()
}

// arpPending holds packets awaiting ARP resolution, bounded per IP.
type arpPending struct {
	mu      sync.Mutex
	entries map[netip.Addr][]Packet
}

func newARPPending() *arpPending {
	return &arpPending{entries: make(map[netip.Addr][]Packet)}
}

// Enqueue stores a copy of pkt for the unresolved IP. Returns true if an ARP
// request should be sent (i.e. this is the first pending packet for this IP).
func (q *arpPending) Enqueue(ip netip.Addr, pkt Packet) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	existing := q.entries[ip]
	first := len(existing) == 0
	if len(existing) < arpPendingMaxPkts {
		// Copy the packet since the original buffer may be reused.
		cp := make(Packet, len(pkt))
		copy(cp, pkt)
		q.entries[ip] = append(existing, cp)
	}
	return first
}

// Drain removes and returns all pending packets for the given IP.
func (q *arpPending) Drain(ip netip.Addr) []Packet {
	q.mu.Lock()
	pkts := q.entries[ip]
	delete(q.entries, ip)
	q.mu.Unlock()
	return pkts
}

// buildARPPacket constructs a 28-byte ARP payload for IPv4-over-Ethernet.
func buildARPPacket(op uint16, senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) []byte {
	buf := make([]byte, 28)
	binary.BigEndian.PutUint16(buf[0:2], 1)      // hardware type: Ethernet
	binary.BigEndian.PutUint16(buf[2:4], 0x0800)  // protocol type: IPv4
	buf[4] = 6                                     // hardware addr len
	buf[5] = 4                                     // protocol addr len
	binary.BigEndian.PutUint16(buf[6:8], op)
	copy(buf[8:14], senderMAC)
	s := senderIP.As4()
	copy(buf[14:18], s[:])
	copy(buf[18:24], targetMAC)
	t := targetIP.As4()
	copy(buf[24:28], t[:])
	return buf
}

// parseARP extracts fields from a 28-byte ARP payload. Returns false if invalid.
func parseARP(payload []byte) (op uint16, senderMAC net.HardwareAddr, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr, ok bool) {
	if len(payload) < 28 {
		return
	}
	// Validate: Ethernet + IPv4
	if binary.BigEndian.Uint16(payload[0:2]) != 1 || binary.BigEndian.Uint16(payload[2:4]) != 0x0800 {
		return
	}
	if payload[4] != 6 || payload[5] != 4 {
		return
	}
	op = binary.BigEndian.Uint16(payload[6:8])
	senderMAC = net.HardwareAddr(make([]byte, 6))
	copy(senderMAC, payload[8:14])
	senderIP = netip.AddrFrom4([4]byte(payload[14:18]))
	targetMAC = net.HardwareAddr(make([]byte, 6))
	copy(targetMAC, payload[18:24])
	targetIP = netip.AddrFrom4([4]byte(payload[24:28]))
	ok = true
	return
}
