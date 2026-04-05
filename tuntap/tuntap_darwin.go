package tuntap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	"github.com/KarpelesLab/pktkit"
	"golang.org/x/sys/unix"
)

const (
	utunControlName = "com.apple.net.utun_control"
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
)

// TUN opens a TUN device via macOS utun.
func TUN(cfg Config) (*L3Dev, error) {
	fd, name, err := openUtun()
	if err != nil {
		return nil, fmt.Errorf("tuntap: open utun: %w", err)
	}

	d := &L3Dev{
		fd:   fd,
		name: name,
		done: make(chan struct{}),
	}
	go d.readLoop()
	return d, nil
}

// TAP is not supported on macOS.
func TAP(_ Config) (*L2Dev, error) {
	return nil, errors.New("tuntap: TAP mode is not supported on macOS")
}

func openUtun() (int, string, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2) // 2 = SYSPROTO_CONTROL
	if err != nil {
		return -1, "", fmt.Errorf("socket AF_SYSTEM: %w", err)
	}

	ctlInfo := &unix.CtlInfo{}
	copy(ctlInfo.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, ctlInfo); err != nil {
		unix.Close(fd)
		return -1, "", fmt.Errorf("ioctl CTLIOCGINFO: %w", err)
	}

	// Try unit numbers starting from 0 until we find one available
	var unit uint32
	for unit = 0; unit < 256; unit++ {
		sa := &unix.SockaddrCtl{
			ID:   ctlInfo.Id,
			Unit: unit,
		}
		if err := unix.Connect(fd, sa); err == nil {
			break
		}
		if unit == 255 {
			unix.Close(fd)
			return -1, "", errors.New("no available utun unit")
		}
	}

	// Get the assigned interface name
	name, err := unix.GetsockoptString(fd, 2 /* SYSPROTO_CONTROL */, utunOptIfname)
	if err != nil {
		// Fallback: construct from unit number
		name = "utun" + strconv.Itoa(int(unit))
	}

	if err := unix.SetNonblock(fd, false); err != nil {
		unix.Close(fd)
		return -1, "", err
	}

	return fd, name, nil
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
		if n <= 4 { // 4-byte protocol header + at least 1 byte
			continue
		}
		// Strip the 4-byte utun header (protocol family)
		pkt := make([]byte, n-4)
		copy(pkt, buf[4:n])
		if h := d.handler.Load(); h != nil {
			(*h)(pktkit.Packet(pkt))
		}
	}
}

func (d *L3Dev) Send(pkt pktkit.Packet) error {
	if len(pkt) == 0 {
		return nil
	}
	// Prepend 4-byte protocol header
	var proto uint32
	switch pkt[0] >> 4 {
	case 4:
		proto = unix.AF_INET
	case 6:
		proto = unix.AF_INET6
	default:
		return errors.New("tuntap: unknown IP version")
	}

	hdr := make([]byte, 4+len(pkt))
	binary.BigEndian.PutUint32(hdr[:4], proto)
	copy(hdr[4:], pkt)

	_, err := unix.Write(d.fd, hdr)
	return err
}

func (d *L3Dev) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		unix.Close(d.fd)
	})
	return nil
}

// --- IP/route configuration (macOS) ---

// SetIPv4 configures an IPv4 point-to-point address on the interface.
func (d *L3Dev) SetIPv4(addr netip.Prefix) error {
	if err := setAddrDarwin(d.name, addr); err != nil {
		return err
	}
	d.addr.Store(addr)
	return setUp(d.name)
}

// SetIPv6 configures an IPv6 address on the interface.
func (d *L3Dev) SetIPv6(addr netip.Prefix) error {
	// Use ifconfig for IPv6
	ip := addr.Addr().String()
	pfx := strconv.Itoa(addr.Bits())
	return exec.Command("ifconfig", d.name, "inet6", ip+"/"+pfx).Run()
}

// AddRoute adds a route via this interface.
func (d *L3Dev) AddRoute(dst netip.Prefix, gw netip.Addr) error {
	dstStr := dst.String()
	if gw.IsValid() && !gw.IsUnspecified() {
		return exec.Command("route", "-n", "add", dstStr, gw.String()).Run()
	}
	return exec.Command("route", "-n", "add", "-interface", d.name, dstStr).Run()
}

// SetMTU sets the interface MTU.
func (d *L3Dev) SetMTU(mtu int) error {
	return setMTU(d.name, mtu)
}

func setAddrDarwin(name string, addr netip.Prefix) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	ip := addr.Addr()
	if !ip.Is4() {
		return errors.New("tuntap: SetIPv4 requires an IPv4 address")
	}

	// Build ifreq with sockaddr_in for SIOCSIFADDR
	var ifr [32]byte
	copy(ifr[:16], name)

	// sockaddr_in at offset 16: len(1) + family(1) + port(2) + addr(4) = 8 bytes min
	sa := (*[16]byte)(unsafe.Pointer(&ifr[16]))
	sa[0] = 16           // sin_len
	sa[1] = unix.AF_INET // sin_family
	ip4 := ip.As4()
	copy(sa[4:8], ip4[:])

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFADDR), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFADDR", errno)
	}

	// Set destination address for point-to-point (same as local for now)
	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFDSTADDR), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFDSTADDR", errno)
	}

	// Set netmask
	ones := addr.Bits()
	mask := net.CIDRMask(ones, 32)
	sa[0] = 16
	sa[1] = unix.AF_INET
	sa[2] = 0
	sa[3] = 0
	copy(sa[4:8], mask)

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFNETMASK), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFNETMASK", errno)
	}

	return nil
}

func setUp(name string) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	var ifr [32]byte
	copy(ifr[:16], name)

	// Get current flags
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCGIFFLAGS", errno)
	}

	flags := *(*uint16)(unsafe.Pointer(&ifr[16]))
	flags |= unix.IFF_UP | unix.IFF_RUNNING
	*(*uint16)(unsafe.Pointer(&ifr[16])) = flags

	_, _, errno = unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFFLAGS", errno)
	}
	return nil
}

func setMTU(name string, mtu int) error {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(sock)

	var ifr [32]byte
	copy(ifr[:16], name)
	*(*int32)(unsafe.Pointer(&ifr[16])) = int32(mtu)

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		return os.NewSyscallError("ioctl SIOCSIFMTU", errno)
	}
	return nil
}
