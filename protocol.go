package pktkit

import "fmt"

// Protocol identifies the IP protocol number carried in an IP packet.
type Protocol uint8

const (
	ProtocolICMP   Protocol = 1
	ProtocolTCP    Protocol = 6
	ProtocolUDP    Protocol = 17
	ProtocolICMPv6 Protocol = 58
)

func (p Protocol) String() string {
	switch p {
	case ProtocolICMP:
		return "ICMP"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolICMPv6:
		return "ICMPv6"
	default:
		return fmt.Sprintf("proto(%d)", uint8(p))
	}
}
