//go:build linux

// Package afxdp implements pktkit.L2Device over Linux AF_XDP sockets,
// providing kernel-bypass Ethernet frame I/O via shared memory ring buffers.
package afxdp

import (
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ring is a UMEM ring buffer (fill or completion) containing uint64 frame addresses.
// The producer and consumer pointers are shared with the kernel via mmap'd memory.
type ring struct {
	producer *uint32  // kernel/app writes (depending on ring direction)
	consumer *uint32  // kernel/app reads (depending on ring direction)
	flags    *uint32  // ring flags (XDP_RING_NEED_WAKEUP)
	addrs    []uint64 // descriptor array of UMEM frame addresses
	mask     uint32   // ringSize - 1 (for modulo)
	size     uint32   // ring size (power of 2)
}

// descRing is a socket ring buffer (RX or TX) containing XDPDesc descriptors.
type descRing struct {
	producer *uint32        // kernel/app writes (depending on ring direction)
	consumer *uint32        // kernel/app reads (depending on ring direction)
	flags    *uint32        // ring flags
	descs    []unix.XDPDesc // descriptor array
	mask     uint32
	size     uint32
}

// --- Fill ring (app produces addresses for kernel to fill with RX packets) ---

// fillProduce enqueues UMEM frame addresses into the fill ring.
// Returns the number of addresses successfully enqueued.
func (r *ring) fillProduce(addrs []uint64) int {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)

	free := r.size - (prod - cons)
	n := uint32(len(addrs))
	if n > free {
		n = free
	}
	if n == 0 {
		return 0
	}

	for i := uint32(0); i < n; i++ {
		r.addrs[(prod+i)&r.mask] = addrs[i]
	}

	// Memory barrier: ensure descriptors are visible before updating producer.
	atomic.StoreUint32(r.producer, prod+n)
	return int(n)
}

// --- Completion ring (kernel produces addresses of transmitted frames) ---

// compConsume dequeues UMEM frame addresses from the completion ring.
// The returned addresses can be reused for TX.
func (r *ring) compConsume(out []uint64) int {
	cons := atomic.LoadUint32(r.consumer)
	prod := atomic.LoadUint32(r.producer)

	avail := prod - cons
	n := uint32(len(out))
	if n > avail {
		n = avail
	}
	if n == 0 {
		return 0
	}

	for i := uint32(0); i < n; i++ {
		out[i] = r.addrs[(cons+i)&r.mask]
	}

	atomic.StoreUint32(r.consumer, cons+n)
	return int(n)
}

// --- RX ring (kernel produces received packet descriptors) ---

// rxConsume dequeues received packet descriptors from the RX ring.
// Returns descriptors that reference data in the UMEM region.
func (r *descRing) rxConsume(out []unix.XDPDesc) int {
	cons := atomic.LoadUint32(r.consumer)
	prod := atomic.LoadUint32(r.producer)

	avail := prod - cons
	n := uint32(len(out))
	if n > avail {
		n = avail
	}
	if n == 0 {
		return 0
	}

	for i := uint32(0); i < n; i++ {
		out[i] = r.descs[(cons+i)&r.mask]
	}

	atomic.StoreUint32(r.consumer, cons+n)
	return int(n)
}

// --- TX ring (app produces packet descriptors for kernel to transmit) ---

// txProduce enqueues packet descriptors into the TX ring.
// Returns the number of descriptors successfully enqueued.
func (r *descRing) txProduce(descs []unix.XDPDesc) int {
	prod := atomic.LoadUint32(r.producer)
	cons := atomic.LoadUint32(r.consumer)

	free := r.size - (prod - cons)
	n := uint32(len(descs))
	if n > free {
		n = free
	}
	if n == 0 {
		return 0
	}

	for i := uint32(0); i < n; i++ {
		r.descs[(prod+i)&r.mask] = descs[i]
	}

	atomic.StoreUint32(r.producer, prod+n)
	return int(n)
}

// needWakeup checks if the kernel needs a wakeup (sendto/poll) to process
// pending TX or fill ring entries.
func (r *descRing) needWakeup() bool {
	if r.flags == nil {
		return true
	}
	return atomic.LoadUint32(r.flags)&unix.XDP_RING_NEED_WAKEUP != 0
}

func (r *ring) needWakeup() bool {
	if r.flags == nil {
		return true
	}
	return atomic.LoadUint32(r.flags)&unix.XDP_RING_NEED_WAKEUP != 0
}

// parseRing sets up a UMEM ring (fill/completion) from mmap'd memory and offsets.
func parseRing(mem []byte, off unix.XDPRingOffset, size uint32) *ring {
	r := &ring{
		producer: (*uint32)(unsafe.Pointer(&mem[off.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&mem[off.Consumer])),
		mask:     size - 1,
		size:     size,
	}
	if off.Flags != 0 {
		r.flags = (*uint32)(unsafe.Pointer(&mem[off.Flags]))
	}
	r.addrs = unsafe.Slice((*uint64)(unsafe.Pointer(&mem[off.Desc])), size)
	return r
}

// parseDescRing sets up a socket ring (RX/TX) from mmap'd memory and offsets.
func parseDescRing(mem []byte, off unix.XDPRingOffset, size uint32) *descRing {
	r := &descRing{
		producer: (*uint32)(unsafe.Pointer(&mem[off.Producer])),
		consumer: (*uint32)(unsafe.Pointer(&mem[off.Consumer])),
		mask:     size - 1,
		size:     size,
	}
	if off.Flags != 0 {
		r.flags = (*uint32)(unsafe.Pointer(&mem[off.Flags]))
	}
	r.descs = unsafe.Slice((*unix.XDPDesc)(unsafe.Pointer(&mem[off.Desc])), size)
	return r
}
