package qemu

import (
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
)

// AdapterConfig configures a qemu [Adapter].
type AdapterConfig struct {
	// Listener accepts incoming qemu socket connections.
	Listener *Listener

	// L2Connector joins every accepted guest into a shared L2 broadcast
	// domain. Use an [*pktkit.L2Hub]. Mutually exclusive with Connector.
	L2Connector pktkit.L2Connector

	// Connector gives each accepted guest its own isolated L3 namespace via
	// ConnectL3. The adapter builds a per-guest mini L2 network containing
	// a gateway bridged to this connector (and optionally a DHCP server).
	// Use a [slirp.Stack] or [nat.NAT]. Mutually exclusive with L2Connector.
	Connector pktkit.L3Connector

	// Gateway is the IP prefix of the per-guest gateway (e.g. 10.0.0.1/24).
	// Required in Connector mode.
	Gateway netip.Prefix

	// DHCP optionally enables a per-guest DHCP server, configured from a
	// template. A fresh DHCPServer is instantiated per guest (each with its
	// own lease table). Used in Connector mode only.
	DHCP *pktkit.DHCPServerConfig
}

// Adapter accepts qemu socket connections and wires each guest either into a
// shared L2 domain (L2Connector) or into its own isolated L3 namespace
// (Connector). In isolated mode, each guest sees a private mini L2 network
// containing a gateway (bridged to the connector via ConnectL3) and, if
// configured, a per-guest DHCP server.
type Adapter struct {
	cfg    AdapterConfig
	mu     sync.Mutex
	guests map[*Conn]*guestState
	closed atomic.Bool
}

type guestState struct {
	cleanup func()
}

// NewAdapter creates a qemu Adapter. Call [Adapter.Serve] to start accepting.
func NewAdapter(cfg AdapterConfig) (*Adapter, error) {
	if cfg.Listener == nil {
		return nil, fmt.Errorf("qemu: Listener is required")
	}
	if cfg.L2Connector == nil && cfg.Connector == nil {
		return nil, fmt.Errorf("qemu: either L2Connector or Connector is required")
	}
	if cfg.L2Connector != nil && cfg.Connector != nil {
		return nil, fmt.Errorf("qemu: L2Connector and Connector are mutually exclusive")
	}
	if cfg.Connector != nil && !cfg.Gateway.IsValid() {
		return nil, fmt.Errorf("qemu: Gateway is required when using Connector")
	}
	return &Adapter{cfg: cfg, guests: make(map[*Conn]*guestState)}, nil
}

// Serve runs the accept loop, blocking until the listener fails or the
// adapter is closed.
func (a *Adapter) Serve() error {
	for {
		conn, err := a.cfg.Listener.Accept()
		if err != nil {
			if a.closed.Load() {
				return nil
			}
			return err
		}
		if a.closed.Load() {
			conn.Close()
			return nil
		}
		if !a.onAccept(conn) {
			conn.Close()
		}
	}
}

func (a *Adapter) onAccept(conn *Conn) bool {
	var cleanup func()

	if a.cfg.L2Connector != nil {
		release, err := a.cfg.L2Connector.ConnectL2(conn)
		if err != nil {
			return false
		}
		cleanup = func() { release() }
	} else {
		br, err := newBridge(a.cfg.Gateway, a.cfg.Connector)
		if err != nil {
			return false
		}

		hub := pktkit.NewL2Hub()
		hub.Connect(br.gwL2)
		hub.Connect(conn)

		var dhcpSrv *pktkit.DHCPServer
		if a.cfg.DHCP != nil {
			tpl := *a.cfg.DHCP
			dhcpSrv = pktkit.NewDHCPServer(tpl)
			hub.Connect(dhcpSrv)
		}

		cleanup = func() {
			br.gwL2.Close()
			br.stackCleanup()
			_ = dhcpSrv // hub goes out of scope after guests map release
		}
	}

	st := &guestState{cleanup: cleanup}
	a.mu.Lock()
	if a.closed.Load() {
		a.mu.Unlock()
		cleanup()
		return false
	}
	a.guests[conn] = st
	a.mu.Unlock()

	go func() {
		<-conn.Done()
		a.mu.Lock()
		_, ok := a.guests[conn]
		if ok {
			delete(a.guests, conn)
		}
		a.mu.Unlock()
		if ok {
			cleanup()
		}
	}()

	return true
}

// Close stops the adapter, closes the listener, and tears down all guests.
func (a *Adapter) Close() error {
	if !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	a.cfg.Listener.Close()

	a.mu.Lock()
	guests := a.guests
	a.guests = make(map[*Conn]*guestState)
	a.mu.Unlock()

	for conn, st := range guests {
		conn.Close()
		st.cleanup()
	}
	return nil
}

// --- L3 bridge plumbing ---
//
// Bridging an L2 qemu guest to an L3Connector requires two distinct L3Devices.
// Both [pktkit.L2Adapter] and stack.ConnectL3 overwrite dev.SetHandler, so a
// single device cannot serve both roles. We use one device per role and wire
// them manually.

type bridge struct {
	gwL2         *pktkit.L2Adapter
	stackEnd     *stackEndDev
	l2End        *l2EndDev
	stackCleanup func() error
}

func newBridge(addr netip.Prefix, connector pktkit.L3Connector) (*bridge, error) {
	b := &bridge{
		stackEnd: &stackEndDev{},
		l2End:    &l2EndDev{},
	}
	b.stackEnd.addr.Store(addr)
	b.l2End.addr.Store(addr)

	// L2 → stack: L2Adapter pushes guest packets into l2End.Send, which
	// forwards to the stack via stackEnd's outbound handler.
	b.l2End.onEgress = func(pkt pktkit.Packet) error {
		if fn := b.stackEnd.outHandler.Load(); fn != nil {
			return (*fn)(pkt)
		}
		return nil
	}
	// Stack → L2: stack ingress arrives via stackEnd.Send, which invokes
	// l2End's (L2Adapter-registered) handler to wrap and send on L2.
	b.stackEnd.onIngress = func(pkt pktkit.Packet) error {
		if h := b.l2End.handler.Load(); h != nil {
			return (*h)(pkt)
		}
		return nil
	}

	b.gwL2 = pktkit.NewL2Adapter(b.l2End, nil)

	cleanup, err := connector.ConnectL3(b.stackEnd)
	if err != nil {
		b.gwL2.Close()
		return nil, err
	}
	b.stackCleanup = cleanup
	return b, nil
}

// stackEndDev is the L3Device handed to the L3Connector.
//
//   - Send is called by the connector on ingress (packets destined for the
//     guest); we forward them to the L2 side via onIngress.
//   - SetHandler is called by the connector to register its outbound
//     delivery (e.g. slirp's side.Send); we store it as outHandler.
type stackEndDev struct {
	addr       atomic.Value
	outHandler atomic.Pointer[func(pktkit.Packet) error]
	onIngress  func(pktkit.Packet) error
}

func (s *stackEndDev) Send(pkt pktkit.Packet) error {
	if s.onIngress != nil {
		return s.onIngress(pkt)
	}
	return nil
}

func (s *stackEndDev) SetHandler(h func(pktkit.Packet) error) {
	s.outHandler.Store(&h)
}

func (s *stackEndDev) Addr() netip.Prefix {
	if v := s.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (s *stackEndDev) SetAddr(p netip.Prefix) error {
	s.addr.Store(p)
	return nil
}

func (s *stackEndDev) Close() error { return nil }

// l2EndDev is the L3Device wrapped by L2Adapter.
//
//   - Send is called by L2Adapter with L3 packets unwrapped from guest
//     frames; we forward them to the stack via onEgress.
//   - SetHandler is called by L2Adapter to register its L2-wrap function;
//     we store it as handler and invoke it for stack-to-guest packets.
type l2EndDev struct {
	addr     atomic.Value
	handler  atomic.Pointer[func(pktkit.Packet) error]
	onEgress func(pktkit.Packet) error
}

func (l *l2EndDev) Send(pkt pktkit.Packet) error {
	if l.onEgress != nil {
		return l.onEgress(pkt)
	}
	return nil
}

func (l *l2EndDev) SetHandler(h func(pktkit.Packet) error) {
	l.handler.Store(&h)
}

func (l *l2EndDev) Addr() netip.Prefix {
	if v := l.addr.Load(); v != nil {
		return v.(netip.Prefix)
	}
	return netip.Prefix{}
}

func (l *l2EndDev) SetAddr(p netip.Prefix) error {
	l.addr.Store(p)
	return nil
}

func (l *l2EndDev) Close() error { return nil }
