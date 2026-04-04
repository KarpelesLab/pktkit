# pktkit

[![Go Reference](https://pkg.go.dev/badge/github.com/KarpelesLab/pktkit.svg)](https://pkg.go.dev/github.com/KarpelesLab/pktkit)
[![Test](https://github.com/KarpelesLab/pktkit/actions/workflows/test.yml/badge.svg)](https://github.com/KarpelesLab/pktkit/actions/workflows/test.yml)
[![Coverage Status](https://coveralls.io/repos/github/KarpelesLab/pktkit/badge.svg?branch=master)](https://coveralls.io/github/KarpelesLab/pktkit?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/KarpelesLab/pktkit)](https://goreportcard.com/report/github.com/KarpelesLab/pktkit)

Zero-copy L2/L3 packet handling library for Go.

pktkit provides primitives for building virtual network topologies: devices, hubs, and adapters that move Ethernet frames and IP packets without copying buffers on the hot path.

## Features

### Core

- **Zero-copy types**: `Frame` and `Packet` are `[]byte` aliases with typed header accessors — no wrapper allocation
- **Callback-based forwarding**: synchronous `func(T) error` handler callbacks matching `Send` signatures, no channels
- **L2Device / L3Device interfaces**: uniform API for all network devices

### Connectivity

- **L2Hub**: broadcast hub connecting multiple L2 devices
- **L3Hub**: routing hub with prefix-based unicast forwarding and broadcast/multicast delivery
- **ConnectL2 / ConnectL3**: point-to-point wiring helpers (`a.SetHandler(b.Send)`)

### Bridging

- **L2Adapter**: bridges an L3 device onto an L2 network with ARP resolution, DHCP client, and gateway routing
- **DHCPServer**: L2 device serving DHCP leases with configurable IP pool, router, and DNS options

### Subpackages

- **slirp**: NAT stack implementing L3Device — routes virtual traffic to the real network via `net.Dial`
- **vclient**: virtual network client implementing L3Device — provides `Dial`, `Listen`, `net.Conn`, DNS, and `http.Client`
- **vtcp**: pure RFC-compliant TCP protocol engine (congestion control, SACK, timestamps, window scaling)

## Usage

### Point-to-point L3

```go
import "github.com/KarpelesLab/pktkit"

tun1 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.1/24"))
tun2 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.2/24"))
pktkit.ConnectL3(tun1, tun2)
```

### Virtual LAN with DHCP and NAT

```go
import (
    "github.com/KarpelesLab/pktkit"
    "github.com/KarpelesLab/pktkit/slirp"
    "github.com/KarpelesLab/pktkit/vclient"
)

// L2 switch
hub := pktkit.NewL2Hub()

// DHCP server
dhcpSrv := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
    ServerIP:   netip.MustParseAddr("192.168.0.1"),
    SubnetMask: net.CIDRMask(24, 32),
    RangeStart: netip.MustParseAddr("192.168.0.10"),
    RangeEnd:   netip.MustParseAddr("192.168.0.100"),
    Router:     netip.MustParseAddr("192.168.0.1"),
    DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
})
hub.Connect(dhcpSrv)

// NAT gateway (slirp routes to real internet)
stack := slirp.New()
stack.SetAddr(netip.MustParsePrefix("192.168.0.1/24"))
hub.Connect(pktkit.NewL2Adapter(stack, net.HardwareAddr{0x02, 0, 0, 0, 0, 1}))

// Virtual client — gets IP via DHCP, can dial out
client := vclient.New()
client.SetIP(net.IPv4zero, net.CIDRMask(0, 32), net.IPv4(192, 168, 0, 1))
client.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})
adapter := pktkit.NewL2Adapter(client, net.HardwareAddr{0x02, 0, 0, 0, 0, 2})
hub.Connect(adapter)
adapter.StartDHCP()

// Use standard Go HTTP client over the virtual network
resp, _ := client.HTTPClient().Get("https://example.com")
```

## License

MIT — see [LICENSE](LICENSE).
