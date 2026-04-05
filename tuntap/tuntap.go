// Package tuntap provides OS-level TUN and TAP devices implementing
// pktkit's [pktkit.L3Device] and [pktkit.L2Device] interfaces.
//
// TUN devices operate at L3 (raw IP packets) and TAP devices at L2
// (Ethernet frames). Both support IP address and route configuration
// on the underlying OS interface.
//
// On Linux, both TUN and TAP modes are supported via /dev/net/tun.
// On macOS, only TUN mode is supported via the utun kernel control.
package tuntap

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
)

// Config configures a TUN or TAP device.
type Config struct {
	// Name is the desired interface name (e.g. "tun0").
	// On macOS, this is ignored (utun names are auto-assigned).
	// If empty on Linux, the kernel assigns a name.
	Name string
}

// L3Dev is a TUN device implementing [pktkit.L3Device].
// It reads and writes raw IP packets from/to the OS network stack.
type L3Dev struct {
	fd        int
	name      string
	handler   atomic.Pointer[func(pktkit.Packet) error]
	addr      atomic.Value // netip.Prefix
	done      chan struct{}
	closeOnce sync.Once
}

// Name returns the OS interface name (e.g. "tun0", "utun3").
func (d *L3Dev) Name() string { return d.name }

func (d *L3Dev) SetHandler(h func(pktkit.Packet) error) {
	d.handler.Store(&h)
}

func (d *L3Dev) Addr() netip.Prefix {
	if v, ok := d.addr.Load().(netip.Prefix); ok {
		return v
	}
	return netip.Prefix{}
}

func (d *L3Dev) SetAddr(p netip.Prefix) error {
	d.addr.Store(p)
	return nil
}

// Done returns a channel that is closed when the device is closed.
func (d *L3Dev) Done() <-chan struct{} { return d.done }

// L2Dev is a TAP device implementing [pktkit.L2Device].
// It reads and writes Ethernet frames from/to the OS network stack.
// TAP mode is not supported on macOS.
type L2Dev struct {
	fd        int
	name      string
	mac       net.HardwareAddr
	handler   atomic.Pointer[func(pktkit.Frame) error]
	done      chan struct{}
	closeOnce sync.Once
}

// Name returns the OS interface name (e.g. "tap0").
func (d *L2Dev) Name() string { return d.name }

func (d *L2Dev) SetHandler(h func(pktkit.Frame) error) {
	d.handler.Store(&h)
}

func (d *L2Dev) HWAddr() net.HardwareAddr { return d.mac }

// Done returns a channel that is closed when the device is closed.
func (d *L2Dev) Done() <-chan struct{} { return d.done }
