package slirp

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/KarpelesLab/pktkit"
)

// ProviderConfig configures the default network parameters for namespaces
// created by a [Provider]. All namespaces share the same configuration
// but maintain fully isolated connection state.
type ProviderConfig struct {
	// Addr is the IP prefix assigned to each namespace's Stack
	// (e.g. "192.168.0.1/24"). Each namespace gets its own Stack
	// with this address — overlapping is safe because they're isolated.
	Addr netip.Prefix

	// Gateway is the default gateway set on the L2Adapter. If zero,
	// no gateway is configured and off-subnet traffic won't route.
	Gateway netip.Addr
}

// Provider is a [pktkit.NamespaceProvider] that creates isolated NAT stacks.
// Each namespace gets its own [Stack] (with independent TCP/UDP connection
// tracking) wrapped in an [pktkit.L2Adapter] for L2 network attachment.
//
// Traffic from each namespace is NATed to the host network via net.Dial,
// independently of all other namespaces.
type Provider struct {
	mu         sync.RWMutex
	namespaces map[string]*slirpNamespace
	config     ProviderConfig
}

type slirpNamespace struct {
	name    string
	stack   *Stack
	adapter *pktkit.L2Adapter
}

func (ns *slirpNamespace) Device() pktkit.L2Device { return ns.adapter }

func (ns *slirpNamespace) Close() error {
	ns.adapter.Close()
	return ns.stack.Close()
}

// NewProvider creates a new slirp namespace provider with the given
// default configuration. Call [Provider.Create] to create namespaces.
func NewProvider(cfg ProviderConfig) *Provider {
	return &Provider{
		namespaces: make(map[string]*slirpNamespace),
		config:     cfg,
	}
}

// Create creates a new isolated namespace with the given name.
// The namespace gets its own [Stack] and [pktkit.L2Adapter] configured
// with the provider's default address and gateway.
func (p *Provider) Create(name string) (pktkit.Namespace, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, exists := p.namespaces[name]; exists {
		return nil, errors.New("namespace already exists: " + name)
	}

	stack := New()
	if p.config.Addr.IsValid() {
		stack.SetAddr(p.config.Addr)
	}

	adapter := pktkit.NewL2Adapter(stack, nil)
	if p.config.Gateway.IsValid() {
		adapter.SetGateway(p.config.Gateway)
	}

	ns := &slirpNamespace{
		name:    name,
		stack:   stack,
		adapter: adapter,
	}
	p.namespaces[name] = ns
	return ns, nil
}

// Get returns the namespace with the given name, or nil if not found.
func (p *Provider) Get(name string) pktkit.Namespace {
	p.mu.RLock()
	ns := p.namespaces[name]
	p.mu.RUnlock()
	if ns == nil {
		return nil
	}
	return ns
}

// Delete destroys the namespace and all its connections.
func (p *Provider) Delete(name string) error {
	p.mu.Lock()
	ns, ok := p.namespaces[name]
	if !ok {
		p.mu.Unlock()
		return errors.New("namespace not found: " + name)
	}
	delete(p.namespaces, name)
	p.mu.Unlock()

	return ns.Close()
}

// List returns the names of all active namespaces in sorted order.
func (p *Provider) List() []string {
	p.mu.RLock()
	names := make([]string, 0, len(p.namespaces))
	for name := range p.namespaces {
		names = append(names, name)
	}
	p.mu.RUnlock()
	sort.Strings(names)
	return names
}

// Close destroys all namespaces and their connections.
func (p *Provider) Close() error {
	p.mu.Lock()
	all := p.namespaces
	p.namespaces = make(map[string]*slirpNamespace)
	p.mu.Unlock()

	var firstErr error
	for _, ns := range all {
		if err := ns.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

var nsCounter atomic.Uint64

// ConnectL2 implements [pktkit.L2Connector]. It creates a new namespace
// with an auto-generated name, wires the device and the namespace's
// gateway into a shared L2Hub, and returns a cleanup function that
// deletes the namespace.
func (p *Provider) ConnectL2(dev pktkit.L2Device) (func() error, error) {
	name := fmt.Sprintf("auto-%d", nsCounter.Add(1))
	ns, err := p.Create(name)
	if err != nil {
		return nil, err
	}

	hub := pktkit.NewL2Hub()
	hub.Connect(ns.Device())
	hub.Connect(dev)

	return func() error {
		return p.Delete(name)
	}, nil
}
