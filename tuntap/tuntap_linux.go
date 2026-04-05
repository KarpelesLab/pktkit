package tuntap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"unsafe"

	"github.com/KarpelesLab/pktkit"
	"golang.org/x/sys/unix"
)

// TUN opens a TUN device (L3, raw IP packets).
func TUN(cfg Config) (*L3Dev, error) {
	fd, name, err := openTuntap(cfg.Name, unix.IFF_TUN|unix.IFF_NO_PI)
	if err != nil {
		return nil, fmt.Errorf("tuntap: open tun: %w", err)
	}

	d := &L3Dev{
		fd:   fd,
		name: name,
		done: make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

// TAP opens a TAP device (L2, Ethernet frames).
func TAP(cfg Config) (*L2Dev, error) {
	fd, name, err := openTuntap(cfg.Name, unix.IFF_TAP|unix.IFF_NO_PI)
	if err != nil {
		return nil, fmt.Errorf("tuntap: open tap: %w", err)
	}

	mac, err := getHWAddr(name)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("tuntap: get mac: %w", err)
	}

	d := &L2Dev{
		fd:   fd,
		name: name,
		mac:  mac,
		done: make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

func openTuntap(name string, flags uint16) (int, string, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}

	var ifr [40]byte // struct ifreq
	if name != "" {
		copy(ifr[:16], name)
	}
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		return -1, "", os.NewSyscallError("ioctl TUNSETIFF", errno)
	}

	// extract assigned name (NUL-terminated in ifr[:16])
	n := 0
	for n < 16 && ifr[n] != 0 {
		n++
	}

	return fd, string(ifr[:n]), nil
}

func getHWAddr(name string) (net.HardwareAddr, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	return iface.HardwareAddr, nil
}

// --- L3Dev (TUN) ---

func (d *L3Dev) readLoop() {
	defer d.closeOnce.Do(func() {
		close(d.done)
		unix.Close(d.fd)
	})
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			return
		}
		if n == 0 {
			continue
		}
		if h := d.handler.Load(); h != nil {
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			(*h)(pktkit.Packet(pkt))
		}
	}
}

func (d *L3Dev) Send(pkt pktkit.Packet) error {
	_, err := unix.Write(d.fd, pkt)
	return err
}

func (d *L3Dev) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		unix.Close(d.fd)
	})
	return nil
}

// --- L2Dev (TAP) ---

func (d *L2Dev) readLoop() {
	defer d.closeOnce.Do(func() {
		close(d.done)
		unix.Close(d.fd)
	})
	buf := make([]byte, 65536)
	for {
		n, err := unix.Read(d.fd, buf)
		if err != nil {
			return
		}
		if n < 14 { // minimum Ethernet frame
			continue
		}
		if h := d.handler.Load(); h != nil {
			frame := make([]byte, n)
			copy(frame, buf[:n])
			(*h)(pktkit.Frame(frame))
		}
	}
}

func (d *L2Dev) Send(f pktkit.Frame) error {
	_, err := unix.Write(d.fd, f)
	return err
}

func (d *L2Dev) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		unix.Close(d.fd)
	})
	return nil
}

// --- IP/route configuration (Linux netlink) ---

// SetIPv4 configures an IPv4 address on the interface and brings it up.
func (d *L3Dev) SetIPv4(addr netip.Prefix) error {
	if err := setAddr(d.name, addr); err != nil {
		return err
	}
	d.addr.Store(addr)
	return setUp(d.name)
}

// SetIPv6 configures an IPv6 address on the interface and brings it up.
func (d *L3Dev) SetIPv6(addr netip.Prefix) error {
	if err := setAddr(d.name, addr); err != nil {
		return err
	}
	return setUp(d.name)
}

// AddRoute adds a route via this interface.
func (d *L3Dev) AddRoute(dst netip.Prefix, gw netip.Addr) error {
	return addRoute(d.name, dst, gw)
}

// SetMTU sets the interface MTU.
func (d *L3Dev) SetMTU(mtu int) error {
	return setMTU(d.name, mtu)
}

// SetIPv4 configures an IPv4 address on the interface and brings it up.
func (d *L2Dev) SetIPv4(addr netip.Prefix) error {
	if err := setAddr(d.name, addr); err != nil {
		return err
	}
	return setUp(d.name)
}

// SetIPv6 configures an IPv6 address on the interface and brings it up.
func (d *L2Dev) SetIPv6(addr netip.Prefix) error {
	if err := setAddr(d.name, addr); err != nil {
		return err
	}
	return setUp(d.name)
}

// AddRoute adds a route via this interface.
func (d *L2Dev) AddRoute(dst netip.Prefix, gw netip.Addr) error {
	return addRoute(d.name, dst, gw)
}

// SetMTU sets the interface MTU.
func (d *L2Dev) SetMTU(mtu int) error {
	return setMTU(d.name, mtu)
}

func ifIndex(name string) (int, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return iface.Index, nil
}

// setAddr sets an IP address on a named interface via netlink.
func setAddr(name string, addr netip.Prefix) error {
	idx, err := ifIndex(name)
	if err != nil {
		return err
	}

	ip := addr.Addr()
	family := unix.AF_INET
	ipBytes := ip.As4()
	ipSlice := ipBytes[:]
	if ip.Is6() {
		family = unix.AF_INET6
		ipBytes6 := ip.As16()
		ipSlice = ipBytes6[:]
	}

	// Build netlink RTM_NEWADDR message
	nlmsg := nlMsgNewAddr(family, addr.Bits(), idx, ipSlice)

	return netlinkExec(nlmsg)
}

// addRoute adds a route via a named interface using netlink.
func addRoute(name string, dst netip.Prefix, gw netip.Addr) error {
	idx, err := ifIndex(name)
	if err != nil {
		return err
	}

	family := unix.AF_INET
	if dst.Addr().Is6() {
		family = unix.AF_INET6
	}

	nlmsg := nlMsgNewRoute(family, dst, gw, idx)
	return netlinkExec(nlmsg)
}

// setUp brings a named interface up.
func setUp(name string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	var ifr [40]byte
	copy(ifr[:16], name)

	// Get current flags
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCGIFFLAGS", errno)
	}

	// Set IFF_UP
	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFFLAGS", errno)
	}
	return nil
}

// setMTU sets the MTU on a named interface.
func setMTU(name string, mtu int) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	var ifr [40]byte
	copy(ifr[:16], name)
	*(*int32)(unsafe.Pointer(&ifr[16])) = int32(mtu)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFMTU", errno)
	}
	return nil
}

// --- Netlink helpers ---

func netlinkExec(msg []byte) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(sock, sa); err != nil {
		return err
	}

	if err := unix.Sendto(sock, msg, 0, sa); err != nil {
		return err
	}

	// Read response
	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(sock, buf, 0)
	if err != nil {
		return err
	}
	if n < 16 {
		return errors.New("netlink: response too short")
	}

	// Check for error in response
	msgType := *(*uint16)(unsafe.Pointer(&buf[4]))
	if msgType == unix.NLMSG_ERROR {
		errno := *(*int32)(unsafe.Pointer(&buf[16]))
		if errno != 0 {
			return fmt.Errorf("netlink: %w", unix.Errno(-errno))
		}
	}
	return nil
}

func nlMsgNewAddr(family int, prefixLen int, ifIndex int, ip []byte) []byte {
	// nlmsghdr (16 bytes) + ifaddrmsg (8 bytes) + IFA_LOCAL attr
	attrLen := 4 + len(ip) // nla_hdr (4) + ip
	totalLen := 16 + 8 + nlAlign(attrLen)

	buf := make([]byte, totalLen)
	// nlmsghdr
	*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(totalLen)                                                             // nlmsg_len
	*(*uint16)(unsafe.Pointer(&buf[4])) = unix.RTM_NEWADDR                                                             // nlmsg_type
	*(*uint16)(unsafe.Pointer(&buf[6])) = unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE // nlmsg_flags
	*(*uint32)(unsafe.Pointer(&buf[8])) = 1                                                                            // nlmsg_seq

	// ifaddrmsg
	buf[16] = byte(family)    // ifa_family
	buf[17] = byte(prefixLen) // ifa_prefixlen
	buf[20] = byte(ifIndex)   // ifa_index (uint32, low byte)
	*(*uint32)(unsafe.Pointer(&buf[20])) = uint32(ifIndex)

	// IFA_LOCAL attribute
	off := 24
	*(*uint16)(unsafe.Pointer(&buf[off])) = uint16(attrLen)  // nla_len
	*(*uint16)(unsafe.Pointer(&buf[off+2])) = unix.IFA_LOCAL // nla_type
	copy(buf[off+4:], ip)

	return buf
}

func nlMsgNewRoute(family int, dst netip.Prefix, gw netip.Addr, ifIndex int) []byte {
	dstIP := dst.Addr()
	var dstBytes, gwBytes []byte
	if dstIP.Is4() {
		b := dstIP.As4()
		dstBytes = b[:]
		b2 := gw.As4()
		gwBytes = b2[:]
	} else {
		b := dstIP.As16()
		dstBytes = b[:]
		b2 := gw.As16()
		gwBytes = b2[:]
	}

	dstAttrLen := 4 + len(dstBytes)
	oifAttrLen := 4 + 4 // uint32 interface index

	totalLen := 16 + 12 + nlAlign(dstAttrLen) + nlAlign(oifAttrLen) // nlmsghdr + rtmsg + attrs
	if gw.IsValid() && !gw.IsUnspecified() {
		gwAttrLen := 4 + len(gwBytes)
		totalLen += nlAlign(gwAttrLen)
	}

	buf := make([]byte, totalLen)
	// nlmsghdr
	*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(totalLen)
	*(*uint16)(unsafe.Pointer(&buf[4])) = unix.RTM_NEWROUTE
	*(*uint16)(unsafe.Pointer(&buf[6])) = unix.NLM_F_REQUEST | unix.NLM_F_ACK | unix.NLM_F_CREATE | unix.NLM_F_REPLACE
	*(*uint32)(unsafe.Pointer(&buf[8])) = 1

	// rtmsg (12 bytes)
	buf[16] = byte(family)           // rtm_family
	buf[17] = byte(dst.Bits())       // rtm_dst_len
	buf[19] = unix.RT_TABLE_MAIN     // rtm_table
	buf[20] = unix.RTPROT_STATIC     // rtm_protocol
	buf[21] = unix.RT_SCOPE_UNIVERSE // rtm_scope
	buf[22] = unix.RTN_UNICAST       // rtm_type

	off := 28

	// RTA_DST
	*(*uint16)(unsafe.Pointer(&buf[off])) = uint16(dstAttrLen)
	*(*uint16)(unsafe.Pointer(&buf[off+2])) = unix.RTA_DST
	copy(buf[off+4:], dstBytes)
	off += nlAlign(dstAttrLen)

	// RTA_GATEWAY (optional)
	if gw.IsValid() && !gw.IsUnspecified() {
		gwAttrLen := 4 + len(gwBytes)
		*(*uint16)(unsafe.Pointer(&buf[off])) = uint16(gwAttrLen)
		*(*uint16)(unsafe.Pointer(&buf[off+2])) = unix.RTA_GATEWAY
		copy(buf[off+4:], gwBytes)
		off += nlAlign(gwAttrLen)
	}

	// RTA_OIF
	*(*uint16)(unsafe.Pointer(&buf[off])) = uint16(oifAttrLen)
	*(*uint16)(unsafe.Pointer(&buf[off+2])) = unix.RTA_OIF
	*(*uint32)(unsafe.Pointer(&buf[off+4])) = uint32(ifIndex)

	return buf
}

func nlAlign(l int) int {
	return (l + 3) &^ 3
}
