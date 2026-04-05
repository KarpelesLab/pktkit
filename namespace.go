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
//   - [slirp.Provider]: each device gets an isolated namespace (cleanup deletes it)
type L2Connector interface {
	ConnectL2(dev L2Device) (cleanup func() error, err error)
}

// L3Connector receives L3Devices and manages their attachment lifecycle.
// This is the natural interface for protocols that operate at the IP layer
// (e.g. WireGuard), avoiding unnecessary L2 framing overhead.
//
// Implementations:
//   - [slirp.Provider]: each device gets an isolated NAT stack (cleanup deletes it)
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

// Namespace represents an isolated network namespace. Each namespace has its
// own connection state and can use IP addresses that overlap with other
// namespaces without conflict. Call Device to obtain the L2Device for
// attaching the namespace to a network (e.g. via an L2Hub), and Close to
// tear down all state when the namespace is no longer needed.
type Namespace interface {
	// Device returns the L2Device for this namespace. Connect it to a hub,
	// adapter, or other L2 device to attach the namespace to a network.
	Device() L2Device

	// Close tears down the namespace and all its connections, listeners,
	// and goroutines.
	Close() error
}

// NamespaceProvider creates and manages isolated network namespaces.
// Each namespace provides an independent L2Device whose traffic is fully
// isolated from other namespaces, even when using overlapping IP addresses.
//
// Implementations include slirp (NAT to host network) and qemu (socket
// bridge to QEMU VMs).
type NamespaceProvider interface {
	// Create creates a new namespace with the given name. Returns an error
	// if a namespace with that name already exists.
	Create(name string) (Namespace, error)

	// Get returns an existing namespace by name, or nil if not found.
	Get(name string) Namespace

	// Delete destroys a namespace and all its connections. Returns an error
	// if the namespace does not exist.
	Delete(name string) error

	// List returns the names of all active namespaces.
	List() []string

	// Close destroys all namespaces and releases all resources.
	Close() error
}
