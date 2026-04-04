package pktkit

import (
	"sync"
	"sync/atomic"
	"time"
)

var portIDCounter atomic.Uint64

func nextPortID() uint64 {
	return portIDCounter.Add(1)
}

type l2Port struct {
	dev L2Device
	id  uint64
}

const macAgingDuration = 5 * time.Minute

type macEntry struct {
	portID  uint64
	expires int64 // UnixNano
}

// L2Hub is a learning switch that forwards Ethernet frames between connected
// devices. It learns source MAC addresses and forwards unicast frames only to
// the port associated with the destination MAC. Unknown unicast, broadcast,
// and multicast frames are flooded to all ports except the source.
//
// It uses a copy-on-write port list for lock-free reads on the hot path
// and a sync.Map for the MAC address table.
type L2Hub struct {
	ports    atomic.Value // []l2Port
	mu       sync.Mutex   // serializes connect/disconnect
	macTable sync.Map     // [6]byte → macEntry
}

// NewL2Hub creates a new L2 learning switch.
func NewL2Hub() *L2Hub {
	h := &L2Hub{}
	h.ports.Store([]l2Port(nil))
	return h
}

// Connect adds a device to the switch. The device's handler is set to forward
// received frames through the switch's learning/forwarding logic. Returns a
// handle whose Close method disconnects the device.
func (h *L2Hub) Connect(dev L2Device) *L2HubHandle {
	id := nextPortID()
	handle := &L2HubHandle{hub: h, id: id}

	h.mu.Lock()
	old := h.ports.Load().([]l2Port)
	newPorts := make([]l2Port, len(old)+1)
	copy(newPorts, old)
	newPorts[len(old)] = l2Port{dev: dev, id: id}
	h.ports.Store(newPorts)
	h.mu.Unlock()

	dev.SetHandler(func(f Frame) error {
		h.forward(f, id)
		return nil
	})

	return handle
}

// forward learns the source MAC and delivers the frame to the appropriate
// port(s). Unicast frames with a known destination go to that port only;
// everything else is flooded.
func (h *L2Hub) forward(f Frame, sourceID uint64) {
	if len(f) < 14 {
		return
	}

	// Learn source MAC → port mapping (only if unknown or changed).
	var srcMAC [6]byte
	copy(srcMAC[:], f[6:12])
	if v, ok := h.macTable.Load(srcMAC); !ok || v.(macEntry).portID != sourceID {
		h.macTable.Store(srcMAC, macEntry{
			portID:  sourceID,
			expires: time.Now().Add(macAgingDuration).UnixNano(),
		})
	}

	ports := h.ports.Load().([]l2Port)

	// Broadcast / multicast → flood.
	if f[0]&1 != 0 {
		for i := range ports {
			if ports[i].id != sourceID {
				ports[i].dev.Send(f)
			}
		}
		return
	}

	// Unicast: look up destination MAC.
	var dstMAC [6]byte
	copy(dstMAC[:], f[0:6])
	if v, ok := h.macTable.Load(dstMAC); ok {
		entry := v.(macEntry)
		if time.Now().UnixNano() < entry.expires {
			// Known destination — send to that port only.
			for i := range ports {
				if ports[i].id == entry.portID && ports[i].id != sourceID {
					ports[i].dev.Send(f)
					return
				}
			}
			// Port no longer exists — fall through to flood.
		}
		// Expired entry — remove and flood.
		h.macTable.Delete(dstMAC)
	}

	// Unknown unicast — flood.
	for i := range ports {
		if ports[i].id != sourceID {
			ports[i].dev.Send(f)
		}
	}
}

func (h *L2Hub) disconnect(id uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	old := h.ports.Load().([]l2Port)
	newPorts := make([]l2Port, 0, len(old))
	for _, p := range old {
		if p.id != id {
			newPorts = append(newPorts, p)
		}
	}
	h.ports.Store(newPorts)

	// Remove MAC entries pointing to this port.
	h.macTable.Range(func(key, value any) bool {
		if value.(macEntry).portID == id {
			h.macTable.Delete(key)
		}
		return true
	})
}

// L2HubHandle is returned by L2Hub.Connect and allows disconnecting a
// device from the switch.
type L2HubHandle struct {
	hub  *L2Hub
	id   uint64
	once sync.Once
}

// Close disconnects the device from the switch. Safe to call multiple times.
func (hh *L2HubHandle) Close() error {
	hh.once.Do(func() {
		hh.hub.disconnect(hh.id)
	})
	return nil
}
