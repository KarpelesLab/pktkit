package pktkit

import (
	"net"
	"net/netip"
)

// L2Device represents a Layer 2 (Ethernet) network device.
//
// SetHandler must be called before the device starts producing frames.
// Send may be called from any goroutine. The Frame passed to the handler is
// only valid for the duration of the callback.
type L2Device interface {
	SetHandler(func(Frame) error)
	Send(Frame) error
	HWAddr() net.HardwareAddr
	Close() error
}

// L3Device represents a Layer 3 (IP) network device.
//
// SetHandler must be called before the device starts producing packets.
// Send may be called from any goroutine. The Packet passed to the handler is
// only valid for the duration of the callback.
//
// Addr returns the device's current IP prefix. SetAddr updates it (e.g. from
// DHCP). Implementations should store the prefix atomically.
type L3Device interface {
	SetHandler(func(Packet) error)
	Send(Packet) error
	Addr() netip.Prefix
	SetAddr(netip.Prefix) error
	Close() error
}
