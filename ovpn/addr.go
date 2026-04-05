package ovpn

import (
	"errors"
	"net"
)

type Addr [19]byte

func addrKey(a net.Addr) (Addr, error) {
	switch addr := a.(type) {
	case *net.TCPAddr:
		k := addr.IP
		if len(k) == 4 {
			// ipv4, convert to ipv6 formatted ipv4
			prefix := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
			k = append(prefix, k...)
		}
		k = append(k, 0x02, byte(addr.Port>>8&0xff), byte(addr.Port&0xff))

		var realKey Addr
		copy(realKey[:], k)
		return realKey, nil
	case *net.UDPAddr:
		k := addr.IP
		if len(k) == 4 {
			// ipv4, convert to ipv6 formatted ipv4
			prefix := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
			k = append(prefix, k...)
		}
		k = append(k, 0x01, byte(addr.Port>>8&0xff), byte(addr.Port&0xff))

		var realKey Addr
		copy(realKey[:], k)
		return realKey, nil
	}

	return Addr{}, errors.New("invalid address provided")
}

func (a Addr) TCPAddr() *net.TCPAddr {
	return &net.TCPAddr{
		IP:   a[0:16],
		Port: int(a[17])<<8 | int(a[18]),
	}
}

func (a Addr) String() string {
	switch a[16] {
	case 0x01:
		return "udp/" + a.TCPAddr().String()
	case 0x02:
		return "tcp/" + a.TCPAddr().String()
	default:
		return a.TCPAddr().String()
	}
}
