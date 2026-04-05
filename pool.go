package pktkit

import "sync"

// DefaultMTU is the default buffer size used by the packet pool.
const DefaultMTU = 1536

// pktPool is a global sync.Pool for packet/frame buffers. Most paths in
// pktkit work with ~1500-byte packets; sharing a single pool across NAT,
// WireGuard, and other subsystems maximises reuse and minimises GC pressure.
var pktPool = sync.Pool{
	New: func() any {
		buf := make([]byte, DefaultMTU)
		return &buf
	},
}

// AllocBuffer returns a byte slice of length n from the global packet pool.
// The returned *[]byte handle must be passed to FreeBuffer when the caller
// is done with the buffer. The slice may have capacity > n.
func AllocBuffer(n int) ([]byte, *[]byte) {
	bufp := pktPool.Get().(*[]byte)
	buf := *bufp
	if cap(buf) < n {
		buf = make([]byte, n)
		*bufp = buf
	}
	return buf[:n], bufp
}

// FreeBuffer returns a buffer obtained from AllocBuffer to the pool.
func FreeBuffer(bufp *[]byte) {
	*bufp = (*bufp)[:cap(*bufp)]
	pktPool.Put(bufp)
}
