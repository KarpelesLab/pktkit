package pktkit

import (
	"sync"
	"sync/atomic"
)

type l3Port struct {
	dev L3Device
	id  uint64
}

// L3Hub is a routing hub that forwards IP packets to the appropriate connected
// device based on destination address prefix matching. Multicast and broadcast
// packets are sent to all ports except the source. A default route can be set
// for packets that don't match any connected prefix.
type L3Hub struct {
	ports        atomic.Value // []l3Port
	mu           sync.Mutex
	defaultRoute atomic.Pointer[uint64] // port ID for default route
}

// NewL3Hub creates a new L3 routing hub.
func NewL3Hub() *L3Hub {
	h := &L3Hub{}
	h.ports.Store([]l3Port(nil))
	return h
}

// Connect adds a device to the hub. The device's handler is set to route
// received packets to the appropriate hub port. Returns a handle whose Close
// method disconnects the device.
func (h *L3Hub) Connect(dev L3Device) *L3HubHandle {
	id := nextPortID()
	handle := &L3HubHandle{hub: h, id: id}

	h.mu.Lock()
	old := h.ports.Load().([]l3Port)
	newPorts := make([]l3Port, len(old)+1)
	copy(newPorts, old)
	newPorts[len(old)] = l3Port{dev: dev, id: id}
	h.ports.Store(newPorts)
	h.mu.Unlock()

	dev.SetHandler(func(pkt Packet) error {
		h.route(pkt, id)
		return nil
	})

	return handle
}

// SetDefaultRoute configures dev as the default route for packets that don't
// match any connected prefix.
func (h *L3Hub) SetDefaultRoute(dev L3Device) {
	ports := h.ports.Load().([]l3Port)
	for i := range ports {
		if ports[i].dev == dev {
			id := ports[i].id
			h.defaultRoute.Store(&id)
			return
		}
	}
}

func (h *L3Hub) route(pkt Packet, sourceID uint64) {
	if !pkt.IsValid() {
		return
	}

	dst := pkt.DstAddr()
	if !dst.IsValid() {
		return
	}

	ports := h.ports.Load().([]l3Port)

	// Broadcast/multicast: send to all except source
	if pkt.IsBroadcast() || pkt.IsMulticast() {
		for i := range ports {
			if ports[i].id != sourceID {
				ports[i].dev.Send(pkt)
			}
		}
		return
	}

	// Unicast: find the port whose prefix contains the destination
	for i := range ports {
		if ports[i].id != sourceID && ports[i].dev.Addr().Contains(dst) {
			ports[i].dev.Send(pkt)
			return
		}
	}

	// No prefix match — use default route if configured
	if dr := h.defaultRoute.Load(); dr != nil {
		for i := range ports {
			if ports[i].id == *dr && ports[i].id != sourceID {
				ports[i].dev.Send(pkt)
				return
			}
		}
	}
}

func (h *L3Hub) disconnect(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.ports.Load().([]l3Port)
	newPorts := make([]l3Port, 0, len(old))
	for _, p := range old {
		if p.id != id {
			newPorts = append(newPorts, p)
		}
	}
	h.ports.Store(newPorts)
}

// L3HubHandle is returned by L3Hub.Connect and allows disconnecting a
// device from the hub.
type L3HubHandle struct {
	hub  *L3Hub
	id   uint64
	once sync.Once
}

// Close disconnects the device from the hub. Safe to call multiple times.
func (hh *L3HubHandle) Close() error {
	hh.once.Do(func() {
		hh.hub.disconnect(hh.id)
	})
	return nil
}
