package pktkit

import (
	"sync"
	"sync/atomic"
)

var portIDCounter atomic.Uint64

func nextPortID() uint64 {
	return portIDCounter.Add(1)
}

type l2Port struct {
	dev L2Device
	id  uint64
}

// L2Hub is a broadcast hub that forwards frames received on any connected
// device to all other connected devices. It uses a copy-on-write port list
// for lock-free reads on the hot path.
type L2Hub struct {
	ports atomic.Value // []l2Port
	mu    sync.Mutex   // serializes connect/disconnect
}

// NewL2Hub creates a new L2 broadcast hub.
func NewL2Hub() *L2Hub {
	h := &L2Hub{}
	h.ports.Store([]l2Port(nil))
	return h
}

// Connect adds a device to the hub. The device's handler is set to forward
// received frames to all other hub ports. Returns a handle whose Close
// method disconnects the device.
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

	dev.SetHandler(func(f Frame) {
		h.broadcast(f, id)
	})

	return handle
}

func (h *L2Hub) broadcast(f Frame, sourceID uint64) {
	ports := h.ports.Load().([]l2Port)
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
}

// L2HubHandle is returned by L2Hub.Connect and allows disconnecting a
// device from the hub.
type L2HubHandle struct {
	hub  *L2Hub
	id   uint64
	once sync.Once
}

// Close disconnects the device from the hub. Safe to call multiple times.
func (hh *L2HubHandle) Close() error {
	hh.once.Do(func() {
		hh.hub.disconnect(hh.id)
	})
	return nil
}
