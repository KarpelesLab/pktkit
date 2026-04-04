package vclient

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/KarpelesLab/pktkit/vtcp"
)

// Dial connects to the address on the named network.
// Supported networks are "tcp", "tcp4", "udp", "udp4".
func (c *Client) Dial(network, address string) (net.Conn, error) {
	return c.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if port < 0 || port > 65535 {
		return nil, errors.New("invalid port")
	}

	// Resolve hostname
	ip := net.ParseIP(host)
	if ip == nil {
		// DNS resolution
		addrs, err := c.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, errors.New("no addresses found for " + host)
		}
		ip = net.ParseIP(addrs[0])
		if ip == nil {
			return nil, errors.New("invalid IP from DNS: " + addrs[0])
		}
	}

	// Determine if this is an IPv6 address.
	// If the host was written as ::ffff:x.x.x.x (contains ":"), keep it as IPv6
	// even though Go's To4() returns non-nil for IPv4-mapped addresses.
	ip4 := ip.To4()
	isIPv6 := ip4 == nil
	if ip4 != nil && strings.Contains(host, ":") {
		isIPv6 = true // IPv4-mapped IPv6 address written in :: notation
	}

	// For networks explicitly requesting IPv6
	switch network {
	case "tcp6", "udp6":
		isIPv6 = true
	}

	// If the resolved address is IPv4 but this client is IPv6-only,
	// convert to IPv4-mapped IPv6 address (::ffff:x.x.x.x) for NAT64.
	if !isIPv6 && ip4 != nil {
		c.mu.RLock()
		hasIP4 := c.ip != [4]byte{}
		hasIP6 := c.ip6 != [16]byte{}
		c.mu.RUnlock()
		if !hasIP4 && hasIP6 {
			// Convert to IPv4-mapped IPv6 address
			ip = ip.To16()
			isIPv6 = true
		}
	}

	if isIPv6 {
		var remoteIP6 [16]byte
		copy(remoteIP6[:], ip.To16())

		c.mu.RLock()
		localIP6 := c.ip6
		c.mu.RUnlock()

		switch network {
		case "tcp", "tcp4", "tcp6":
			return c.dialTCP6(ctx, localIP6, remoteIP6, uint16(port))
		case "udp", "udp4", "udp6":
			return c.dialUDP6(localIP6, remoteIP6, uint16(port))
		default:
			return nil, errors.New("unsupported network: " + network)
		}
	}

	var remoteIP [4]byte
	copy(remoteIP[:], ip4)

	c.mu.RLock()
	localIP := c.ip
	c.mu.RUnlock()

	switch network {
	case "tcp", "tcp4":
		return c.dialTCP(ctx, localIP, remoteIP, uint16(port))
	case "udp", "udp4":
		return c.dialUDP(localIP, remoteIP, uint16(port))
	default:
		return nil, errors.New("unsupported network: " + network)
	}
}

func (c *Client) dialTCP(ctx context.Context, localIP, remoteIP [4]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()

	localAddr := &net.TCPAddr{IP: net.IP(localIP[:]).To4(), Port: int(localPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(remoteIP[:]).To4(), Port: int(remotePort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  localPort,
		RemotePort: remotePort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv4Packet(localIP, remoteIP, tcpSeg))
		},
		MSS:       1460,
		Keepalive: true,
	})

	k := connKey{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	conn := &TCPConn{vc: vc, c: c, k: k}

	c.tcpMu.Lock()
	c.tcpConns[k] = conn
	c.tcpMu.Unlock()

	// Initiate handshake
	if err := vc.Connect(ctx); err != nil {
		c.tcpMu.Lock()
		delete(c.tcpConns, k)
		c.tcpMu.Unlock()
		return nil, err
	}

	return conn, nil
}

func (c *Client) dialUDP(localIP, remoteIP [4]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()
	conn := newUDPConn(c, localIP, localPort, remoteIP, remotePort)

	k := connKey{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	c.udpMu.Lock()
	c.udpConns[k] = conn
	c.udpMu.Unlock()

	return conn, nil
}

func (c *Client) dialTCP6(ctx context.Context, localIP, remoteIP [16]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()

	localAddr := &net.TCPAddr{IP: net.IP(localIP[:]), Port: int(localPort)}
	remoteAddr := &net.TCPAddr{IP: net.IP(remoteIP[:]), Port: int(remotePort)}

	vc := vtcp.NewConn(vtcp.ConnConfig{
		LocalPort:  localPort,
		RemotePort: remotePort,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Writer: func(tcpSeg []byte) error {
			return c.sendPacket(buildIPv6Packet(localIP, remoteIP, tcpSeg))
		},
		MSS:       1440,
		Keepalive: true,
	})

	k := connKey6{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	conn := &TCPConn{vc: vc, c: c, k6: k, v6: true}

	c.tcpMu.Lock()
	c.tcpConns6[k] = conn
	c.tcpMu.Unlock()

	// Initiate handshake
	if err := vc.Connect(ctx); err != nil {
		c.tcpMu.Lock()
		delete(c.tcpConns6, k)
		c.tcpMu.Unlock()
		return nil, err
	}

	return conn, nil
}

func (c *Client) dialUDP6(localIP, remoteIP [16]byte, remotePort uint16) (net.Conn, error) {
	localPort := c.allocPort()
	conn := newUDPConn6(c, localIP, localPort, remoteIP, remotePort)

	k := connKey6{localPort: localPort, remoteIP: remoteIP, remotePort: remotePort}
	c.udpMu.Lock()
	c.udpConns6[k] = conn
	c.udpMu.Unlock()

	return conn, nil
}

// HTTPClient returns an *http.Client configured to route all traffic through
// this virtual network client, including DNS resolution via DialContext which
// internally calls LookupHost.
func (c *Client) HTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: c.DialContext,
		},
	}
}
