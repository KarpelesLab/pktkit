package pktkit

import "fmt"

// EtherType identifies the protocol encapsulated in an Ethernet frame payload.
type EtherType uint16

const (
	EtherTypeIPv4 EtherType = 0x0800
	EtherTypeARP  EtherType = 0x0806
	EtherTypeVLAN EtherType = 0x8100
	EtherTypeIPv6 EtherType = 0x86DD
)

func (e EtherType) String() string {
	switch e {
	case EtherTypeIPv4:
		return "IPv4"
	case EtherTypeARP:
		return "ARP"
	case EtherTypeVLAN:
		return "802.1Q"
	case EtherTypeIPv6:
		return "IPv6"
	default:
		return fmt.Sprintf("0x%04x", uint16(e))
	}
}
