package pktkit

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
