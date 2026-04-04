package pktkit

import (
	"net"
	"net/netip"
	"sync/atomic"
)

// PipeL2 is a simple in-memory L2Device useful for testing and for wiring
// devices in subpackages. Frames sent to it are forwarded to the handler.
type PipeL2 struct {
	handler atomic.Pointer[func(Frame)]
	mac     net.HardwareAddr
}

// NewPipeL2 creates a PipeL2 with the given MAC address.
func NewPipeL2(mac net.HardwareAddr) *PipeL2 {
	return &PipeL2{mac: mac}
}

func (p *PipeL2) SetHandler(h func(Frame)) {
	p.handler.Store(&h)
}

func (p *PipeL2) Send(f Frame) error {
	if h := p.handler.Load(); h != nil {
		(*h)(f)
	}
	return nil
}

func (p *PipeL2) HWAddr() net.HardwareAddr { return p.mac }
func (p *PipeL2) Close() error             { return nil }

// Inject pushes a frame into the pipe as if it were received from the
// network, triggering the handler.
func (p *PipeL2) Inject(f Frame) {
	if h := p.handler.Load(); h != nil {
		(*h)(f)
	}
}

// PipeL3 is a simple in-memory L3Device useful for testing.
type PipeL3 struct {
	handler atomic.Pointer[func(Packet)]
	addr    atomic.Value // netip.Prefix
}

// NewPipeL3 creates a PipeL3 with the given IP prefix.
func NewPipeL3(addr netip.Prefix) *PipeL3 {
	p := &PipeL3{}
	p.addr.Store(addr)
	return p
}

func (p *PipeL3) SetHandler(h func(Packet)) {
	p.handler.Store(&h)
}

func (p *PipeL3) Send(pkt Packet) error {
	if h := p.handler.Load(); h != nil {
		(*h)(pkt)
	}
	return nil
}

func (p *PipeL3) Addr() netip.Prefix {
	v := p.addr.Load()
	if v == nil {
		return netip.Prefix{}
	}
	return v.(netip.Prefix)
}

func (p *PipeL3) SetAddr(prefix netip.Prefix) error {
	p.addr.Store(prefix)
	return nil
}

func (p *PipeL3) Close() error { return nil }

// Inject pushes a packet into the pipe as if it were received from the
// network, triggering the handler.
func (p *PipeL3) Inject(pkt Packet) {
	if h := p.handler.Load(); h != nil {
		(*h)(pkt)
	}
}
