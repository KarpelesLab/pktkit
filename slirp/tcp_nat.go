package slirp

import (
	"io"
	"net"
	"sync"

	"github.com/KarpelesLab/pktkit/vtcp"
)

// tcpNATConn bridges a vtcp.Conn (protocol engine facing the virtual client)
// to a real net.Conn (connection to the remote server). This replaces the
// old tcpConn / tcpConn6 types.
type tcpNATConn struct {
	vc        *vtcp.Conn // TCP protocol engine (facing the virtual client)
	remote    net.Conn   // real connection to the destination server
	closeOnce sync.Once
}

// startBridge launches goroutines to copy data bidirectionally between
// the vtcp.Conn and the real connection. When either side closes, the
// other is closed too.
func (n *tcpNATConn) startBridge() {
	// Remote → Client: read from real server, write to vtcp.Conn (which sends to client)
	go func() {
		io.Copy(n.vc, n.remote)
		// Remote closed or errored — close the vtcp.Conn (sends FIN to client)
		n.vc.Close()
	}()

	// Client → Remote: read from vtcp.Conn (data from client), write to real server
	go func() {
		io.Copy(n.remote, n.vc)
		// Client closed or errored — half-close the real connection
		if tc, ok := n.remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
}

// close shuts down both connections. Safe to call from multiple goroutines.
func (n *tcpNATConn) close() {
	n.closeOnce.Do(func() {
		if n.remote != nil {
			n.remote.Close()
		}
		n.vc.Abort()
	})
}
