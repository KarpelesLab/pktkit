//go:build !windows

package qemu

import (
	"net"
	"os"
	"syscall"
)

// Socketpair creates a pair of connected [Conn] values using OS
// socketpair(2). Both ends implement [pktkit.L2Device].
func Socketpair() (a, b *Conn, err error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}

	fa := os.NewFile(uintptr(fds[0]), "qemu-socketpair-a")
	fb := os.NewFile(uintptr(fds[1]), "qemu-socketpair-b")

	connA, err := net.FileConn(fa)
	fa.Close() // FileConn dups the fd
	if err != nil {
		fb.Close()
		return nil, nil, err
	}

	connB, err := net.FileConn(fb)
	fb.Close()
	if err != nil {
		connA.Close()
		return nil, nil, err
	}

	return newConn(connA), newConn(connB), nil
}
