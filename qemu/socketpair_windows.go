package qemu

import "net"

// Socketpair creates a pair of connected [Conn] values.
// On Windows, socketpair(2) is not available, so we emulate it
// using a TCP loopback listener.
func Socketpair() (a, b *Conn, err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	defer ln.Close()

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- c
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	select {
	case serverConn := <-connCh:
		return newConn(clientConn), newConn(serverConn), nil
	case err := <-errCh:
		clientConn.Close()
		return nil, nil, err
	}
}
