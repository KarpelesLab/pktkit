// Package qemu implements QEMU's userspace network socket protocol.
//
// QEMU's -netdev socket (and the newer -netdev stream) uses a simple L2
// framing protocol over stream sockets: each Ethernet frame is prefixed
// with a 4-byte big-endian uint32 length. There is no handshake.
//
// This package provides [Conn], an [pktkit.L2Device] that wraps any
// stream-oriented [net.Conn] (TCP or Unix). Use [Dial] and [Listen]
// for TCP/Unix client-server setups, or [Socketpair] for an in-process
// pair connected via OS socketpair(2).
package qemu

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/KarpelesLab/pktkit"
)

const maxFrameSize = 65535

// Conn wraps a stream connection and implements [pktkit.L2Device].
// Each Ethernet frame is length-prefixed with a 4-byte big-endian uint32.
type Conn struct {
	conn    net.Conn
	mac     net.HardwareAddr
	handler atomic.Pointer[func(pktkit.Frame) error]
	writeMu sync.Mutex
	done    chan struct{}
	closeOnce sync.Once
}

func newConn(conn net.Conn) *Conn {
	mac := make(net.HardwareAddr, 6)
	rand.Read(mac)
	mac[0] = mac[0]&0xFE | 0x02 // locally administered, unicast

	c := &Conn{
		conn: conn,
		mac:  mac,
		done: make(chan struct{}),
	}
	go c.readLoop()
	return c
}

// SetHandler sets the callback invoked for each received Ethernet frame.
// The Frame is only valid for the duration of the callback.
func (c *Conn) SetHandler(h func(pktkit.Frame) error) {
	c.handler.Store(&h)
}

// Send writes an Ethernet frame to the connection, prefixed with its
// 4-byte big-endian length. Safe for concurrent use.
func (c *Conn) Send(f pktkit.Frame) error {
	if len(f) < 14 {
		return nil
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(f)))

	c.writeMu.Lock()
	// Use writev via net.Buffers to send header + frame in one syscall.
	bufs := net.Buffers{hdr[:], f}
	_, err := bufs.WriteTo(c.conn)
	c.writeMu.Unlock()
	return err
}

// HWAddr returns the connection's MAC address.
func (c *Conn) HWAddr() net.HardwareAddr { return c.mac }

// Close shuts down the connection and stops the read goroutine.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.conn.Close()
	})
	return err
}

func (c *Conn) readLoop() {
	var hdr [4]byte
	buf := make([]byte, maxFrameSize)
	for {
		// Read 4-byte length prefix.
		if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
			return
		}
		frameLen := binary.BigEndian.Uint32(hdr[:])
		if frameLen < 14 || frameLen > maxFrameSize {
			return // invalid frame length
		}

		// Read the frame.
		frame := buf[:frameLen]
		if _, err := io.ReadFull(c.conn, frame); err != nil {
			return
		}

		if h := c.handler.Load(); h != nil {
			(*h)(pktkit.Frame(frame))
		}
	}
}

// Dial connects to a QEMU socket netdev at the given address and returns
// a [Conn] implementing [pktkit.L2Device]. Network must be "tcp", "tcp4",
// "tcp6", or "unix".
func Dial(network, address string) (*Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return newConn(conn), nil
}

// Listener accepts incoming QEMU socket connections.
type Listener struct {
	inner net.Listener
}

// Listen creates a [Listener] on the given network and address.
// Network must be "tcp", "tcp4", "tcp6", or "unix".
func Listen(network, address string) (*Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &Listener{inner: ln}, nil
}

// Accept waits for and returns the next connection as a [Conn]
// implementing [pktkit.L2Device].
func (l *Listener) Accept() (*Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return newConn(conn), nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.inner.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.inner.Addr()
}

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
