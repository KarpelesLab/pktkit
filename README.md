# pktkit

Zero-copy L2/L3 packet handling library for Go.

pktkit provides primitives for building virtual network topologies: devices, hubs, and adapters that move Ethernet frames and IP packets without copying buffers on the hot path.

## Features

- **Zero-copy types**: `Frame` and `Packet` are `[]byte` aliases with typed header accessors — no wrapper allocation
- **Callback-based forwarding**: synchronous handler callbacks, no channels
- **L2Hub**: broadcast hub connecting multiple L2 devices
- **L3Hub**: routing hub with prefix-based unicast forwarding and broadcast/multicast delivery
- **L2Adapter**: bridges an L3 device onto an L2 network, handling ARP resolution and DHCP
- **Lock-free hot path**: hubs use copy-on-write atomic port lists

## Usage

```go
import "github.com/KarpelesLab/pktkit"

// Connect two L3 devices directly
tun1 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.1/24"))
tun2 := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.2/24"))
pktkit.ConnectL3(tun1, tun2)

// Or use an L2 hub with an adapter for L3 devices
hub := pktkit.NewL2Hub()
tap := pktkit.NewPipeL2(net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
hub.Connect(tap)

l3dev := pktkit.NewPipeL3(netip.MustParsePrefix("10.0.0.2/24"))
adapter := pktkit.NewL2Adapter(l3dev, net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
hub.Connect(adapter)
```

## License

MIT — see [LICENSE](LICENSE).
