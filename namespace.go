package pktkit

// L2Acceptor produces L2Devices, typically from incoming network connections.
// [qemu.Listener] implements this interface.
type L2Acceptor interface {
	AcceptL2() (L2Device, error)
}

// L2Connector receives L2Devices and manages their attachment lifecycle.
// When the returned cleanup function is called, the device is detached.
//
// Implementations:
//   - [*L2Hub]: all devices join the shared hub (cleanup disconnects)
type L2Connector interface {
	ConnectL2(dev L2Device) (cleanup func() error, err error)
}

// L3Connector receives L3Devices and manages their attachment lifecycle.
// This is the natural interface for protocols that operate at the IP layer
// (e.g. WireGuard), avoiding unnecessary L2 framing overhead.
//
// Implementations:
//   - [slirp.Stack]: each device gets a namespace-isolated NAT (cleanup removes it)
//   - [nat.NAT]: each device gets a namespace-isolated NAT (cleanup removes it)
type L3Connector interface {
	ConnectL3(dev L3Device) (cleanup func() error, err error)
}

// Serve runs an accept loop, connecting each accepted L2Device to the
// connector. If the accepted device implements a Done() <-chan struct{}
// method (e.g. [qemu.Conn]), cleanup is called automatically when the
// device's connection closes. Blocks until the acceptor returns an error.
func Serve(acceptor L2Acceptor, connector L2Connector) error {
	for {
		dev, err := acceptor.AcceptL2()
		if err != nil {
			return err
		}
		cleanup, err := connector.ConnectL2(dev)
		if err != nil {
			dev.Close()
			continue
		}
		// If the device can signal close, auto-cleanup in the background.
		type closeable interface {
			Done() <-chan struct{}
		}
		if c, ok := dev.(closeable); ok {
			go func() {
				<-c.Done()
				cleanup()
			}()
		}
	}
}
