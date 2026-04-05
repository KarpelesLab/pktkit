//go:build linux

package afxdp

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/KarpelesLab/pktkit"
	"golang.org/x/sys/unix"
)

// Default configuration values.
const (
	defaultRingSize  = 2048
	defaultFrameSize = 4096
	defaultNumFrames = 4096
)

// Errors returned by Device operations.
var (
	ErrNoBuffers = errors.New("afxdp: no free TX buffers")
	ErrClosed    = errors.New("afxdp: device closed")
)

// Config configures an AF_XDP device.
type Config struct {
	// Interface is the network interface name (e.g. "eth0").
	Interface string

	// QueueID is the NIC hardware queue to bind to (usually 0).
	QueueID int

	// RingSize is the size of each ring buffer (must be a power of 2).
	// Default: 2048.
	RingSize int

	// FrameSize is the size of each UMEM frame in bytes.
	// Default: 4096.
	FrameSize int

	// NumFrames is the total number of UMEM frames.
	// Default: 4096. Half are used for RX, half for TX.
	NumFrames int

	// Copy forces XDP_COPY mode. By default the driver tries zero-copy
	// first and falls back to copy mode if the NIC doesn't support it.
	Copy bool

	// XSKMapFD, if > 0, uses an existing XSKMAP instead of loading a
	// BPF program automatically. The caller is responsible for loading
	// their own XDP program and creating the map.
	XSKMapFD int

	// Flags are additional XDP socket bind flags (e.g. unix.XDP_USE_NEED_WAKEUP).
	Flags uint16
}

// Device is an L2 network device backed by a Linux AF_XDP socket.
// It implements [pktkit.L2Device].
type Device struct {
	fd      int
	ifindex int
	queueID int
	mac     net.HardwareAddr
	handler atomic.Pointer[func(pktkit.Frame) error]

	done      chan struct{}
	closeOnce sync.Once

	// UMEM
	umem      []byte // mmap'd shared memory
	frameSize int
	numFrames int

	// Rings
	fillRing *ring
	compRing *ring
	rxRing   *descRing
	txRing   *descRing

	// Ring mmap regions (for munmap on close)
	fillMem []byte
	compMem []byte
	rxMem   []byte
	txMem   []byte

	// TX frame pool
	txMu      sync.Mutex
	freeAddrs []uint64

	// BPF resources (-1 if user-provided)
	bpfProgFD int
	bpfMapFD  int
	ownBPF    bool // true if we loaded the BPF program
}

// New creates a new AF_XDP device bound to the given interface and queue.
// It sets up UMEM, ring buffers, and optionally loads a minimal XDP BPF program.
func New(cfg Config) (*Device, error) {
	if cfg.RingSize == 0 {
		cfg.RingSize = defaultRingSize
	}
	if cfg.FrameSize == 0 {
		cfg.FrameSize = defaultFrameSize
	}
	if cfg.NumFrames == 0 {
		cfg.NumFrames = defaultNumFrames
	}
	// Ensure power of 2
	if cfg.RingSize&(cfg.RingSize-1) != 0 {
		return nil, fmt.Errorf("afxdp: RingSize must be a power of 2, got %d", cfg.RingSize)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("afxdp: interface %q: %w", cfg.Interface, err)
	}

	d := &Device{
		fd:        -1,
		ifindex:   iface.Index,
		queueID:   cfg.QueueID,
		mac:       iface.HardwareAddr,
		done:      make(chan struct{}),
		frameSize: cfg.FrameSize,
		numFrames: cfg.NumFrames,
		bpfProgFD: -1,
		bpfMapFD:  -1,
	}

	// Cleanup on failure
	ok := false
	defer func() {
		if !ok {
			d.cleanup()
		}
	}()

	// 1. Create AF_XDP socket
	d.fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("afxdp: socket: %w", err)
	}

	// 2. Allocate UMEM
	umemSize := cfg.NumFrames * cfg.FrameSize
	d.umem, err = unix.Mmap(-1, 0, umemSize,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("afxdp: mmap UMEM: %w", err)
	}

	// 3. Register UMEM
	umemReg := unix.XDPUmemReg{
		Addr: uint64(uintptr(unsafe.Pointer(&d.umem[0]))),
		Len:  uint64(umemSize),
		Size: uint32(cfg.FrameSize),
	}
	if err := setsockoptUmemReg(d.fd, &umemReg); err != nil {
		return nil, fmt.Errorf("afxdp: XDP_UMEM_REG: %w", err)
	}

	// 4. Set ring sizes
	ringSize := uint32(cfg.RingSize)
	for _, opt := range []int{unix.XDP_UMEM_FILL_RING, unix.XDP_UMEM_COMPLETION_RING, unix.XDP_RX_RING, unix.XDP_TX_RING} {
		if err := setsockoptUint32(d.fd, opt, ringSize); err != nil {
			return nil, fmt.Errorf("afxdp: setsockopt ring %d: %w", opt, err)
		}
	}

	// 5. Get mmap offsets
	offsets, err := getsockoptMmapOffsets(d.fd)
	if err != nil {
		return nil, fmt.Errorf("afxdp: XDP_MMAP_OFFSETS: %w", err)
	}

	// 6. Mmap each ring
	d.fillMem, err = mmapRing(d.fd, unix.XDP_UMEM_PGOFF_FILL_RING, offsets.Fr, ringSize)
	if err != nil {
		return nil, fmt.Errorf("afxdp: mmap fill ring: %w", err)
	}
	d.compMem, err = mmapRing(d.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, offsets.Cr, ringSize)
	if err != nil {
		return nil, fmt.Errorf("afxdp: mmap completion ring: %w", err)
	}
	d.rxMem, err = mmapRing(d.fd, unix.XDP_PGOFF_RX_RING, offsets.Rx, ringSize)
	if err != nil {
		return nil, fmt.Errorf("afxdp: mmap RX ring: %w", err)
	}
	d.txMem, err = mmapRing(d.fd, unix.XDP_PGOFF_TX_RING, offsets.Tx, ringSize)
	if err != nil {
		return nil, fmt.Errorf("afxdp: mmap TX ring: %w", err)
	}

	// 7. Parse ring structures
	d.fillRing = parseRing(d.fillMem, offsets.Fr, ringSize)
	d.compRing = parseRing(d.compMem, offsets.Cr, ringSize)
	d.rxRing = parseDescRing(d.rxMem, offsets.Rx, ringSize)
	d.txRing = parseDescRing(d.txMem, offsets.Tx, ringSize)

	// 8. Split UMEM: first half for RX, second half for TX
	rxFrames := cfg.NumFrames / 2
	txFrames := cfg.NumFrames - rxFrames

	// Pre-fill the fill ring with RX frame addresses
	rxAddrs := make([]uint64, rxFrames)
	for i := range rxAddrs {
		rxAddrs[i] = uint64(i * cfg.FrameSize)
	}
	d.fillRing.fillProduce(rxAddrs)

	// Initialize TX free pool
	d.freeAddrs = make([]uint64, txFrames)
	for i := range d.freeAddrs {
		d.freeAddrs[i] = uint64((rxFrames + i) * cfg.FrameSize)
	}

	// 9. Load BPF program (or use user-provided XSKMAP)
	mapFD := cfg.XSKMapFD
	if mapFD <= 0 {
		progFD, mfd, err := loadXDPProgram(64)
		if err != nil {
			return nil, fmt.Errorf("afxdp: load BPF: %w", err)
		}
		d.bpfProgFD = progFD
		d.bpfMapFD = mfd
		d.ownBPF = true
		mapFD = mfd

		// Attach to interface
		xdpFlags := uint32(unix.XDP_FLAGS_SKB_MODE)
		if err := attachXDP(iface.Index, progFD, xdpFlags); err != nil {
			return nil, fmt.Errorf("afxdp: attach XDP: %w", err)
		}
	} else {
		d.bpfMapFD = mapFD
	}

	// 10. Bind socket
	bindFlags := uint16(0)
	if cfg.Copy {
		bindFlags |= unix.XDP_COPY
	}
	bindFlags |= cfg.Flags

	sa := unix.SockaddrXDP{
		Flags:   bindFlags,
		Ifindex: uint32(iface.Index),
		QueueID: uint32(cfg.QueueID),
	}

	err = unix.Bind(d.fd, &sa)
	if err != nil && !cfg.Copy && bindFlags&unix.XDP_ZEROCOPY != 0 {
		// Zero-copy failed, retry with copy mode
		sa.Flags = (bindFlags &^ unix.XDP_ZEROCOPY) | unix.XDP_COPY
		err = unix.Bind(d.fd, &sa)
	}
	if err != nil {
		return nil, fmt.Errorf("afxdp: bind: %w", err)
	}

	// 11. Insert socket into XSKMAP
	if err := updateXSKMap(mapFD, cfg.QueueID, d.fd); err != nil {
		return nil, fmt.Errorf("afxdp: update XSKMAP: %w", err)
	}

	// 12. Start poll loop
	go d.pollLoop()

	ok = true
	return d, nil
}

// SetHandler sets the callback invoked for each received Ethernet frame.
func (d *Device) SetHandler(h func(pktkit.Frame) error) {
	d.handler.Store(&h)
}

// Send transmits an Ethernet frame via the AF_XDP socket.
func (d *Device) Send(f pktkit.Frame) error {
	if len(f) < 14 {
		return nil
	}

	d.txMu.Lock()
	defer d.txMu.Unlock()

	// Try to reclaim completed TX frames first
	d.reclaimTX()

	if len(d.freeAddrs) == 0 {
		return ErrNoBuffers
	}

	// Pop a free UMEM address
	addr := d.freeAddrs[len(d.freeAddrs)-1]
	d.freeAddrs = d.freeAddrs[:len(d.freeAddrs)-1]

	// Copy frame into UMEM
	frameLen := len(f)
	if frameLen > d.frameSize {
		frameLen = d.frameSize
	}
	copy(d.umem[addr:addr+uint64(frameLen)], f[:frameLen])

	// Enqueue TX descriptor
	desc := [1]unix.XDPDesc{{Addr: addr, Len: uint32(frameLen)}}
	if d.txRing.txProduce(desc[:]) == 0 {
		// TX ring full — return address to pool
		d.freeAddrs = append(d.freeAddrs, addr)
		return ErrNoBuffers
	}

	// Kick kernel if needed
	if d.txRing.needWakeup() {
		unix.Sendto(d.fd, nil, unix.MSG_DONTWAIT, nil)
	}

	return nil
}

// HWAddr returns the hardware (MAC) address of the underlying interface.
func (d *Device) HWAddr() net.HardwareAddr {
	return d.mac
}

// Close shuts down the device, unmaps memory, and detaches BPF.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		d.cleanup()
	})
	return nil
}

// Done returns a channel that is closed when the device is shut down.
func (d *Device) Done() <-chan struct{} {
	return d.done
}

// Statistics returns AF_XDP socket statistics.
func (d *Device) Statistics() (unix.XDPStatistics, error) {
	return getsockoptStatistics(d.fd)
}

// pollLoop runs in a goroutine, polling for received frames.
func (d *Device) pollLoop() {
	defer d.Close()

	rxBatch := make([]unix.XDPDesc, 64)
	fillBatch := make([]uint64, 64)

	for {
		// Poll for RX readiness
		fds := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 1000) // 1 second timeout
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			select {
			case <-d.done:
				return
			default:
			}
			return
		}

		select {
		case <-d.done:
			return
		default:
		}

		if n == 0 {
			continue
		}

		// Consume received frames from RX ring
		got := d.rxRing.rxConsume(rxBatch)
		if got == 0 {
			continue
		}

		h := d.handler.Load()
		fillCount := 0

		for i := 0; i < got; i++ {
			desc := rxBatch[i]
			addr := desc.Addr
			length := desc.Len

			if h != nil && length >= 14 {
				// Copy frame data (UMEM is shared with kernel)
				frame := make([]byte, length)
				copy(frame, d.umem[addr:addr+uint64(length)])
				(*h)(pktkit.Frame(frame))
			}

			// Return this UMEM address to the fill ring
			fillBatch[fillCount] = addr
			fillCount++
		}

		// Refill the fill ring so kernel can reuse these addresses
		if fillCount > 0 {
			d.fillRing.fillProduce(fillBatch[:fillCount])
		}

		// If fill ring needs wakeup, recvfrom/poll will handle it
		// on the next iteration.
	}
}

// reclaimTX drains the completion ring and returns addresses to the free pool.
// Must be called with txMu held.
func (d *Device) reclaimTX() {
	var batch [64]uint64
	for {
		n := d.compRing.compConsume(batch[:])
		if n == 0 {
			return
		}
		d.freeAddrs = append(d.freeAddrs, batch[:n]...)
	}
}

// cleanup releases all resources.
func (d *Device) cleanup() {
	if d.ownBPF && d.ifindex > 0 {
		detachXDP(d.ifindex)
	}
	if d.bpfProgFD >= 0 && d.ownBPF {
		unix.Close(d.bpfProgFD)
		d.bpfProgFD = -1
	}
	if d.bpfMapFD >= 0 && d.ownBPF {
		unix.Close(d.bpfMapFD)
		d.bpfMapFD = -1
	}
	if d.rxMem != nil {
		unix.Munmap(d.rxMem)
	}
	if d.txMem != nil {
		unix.Munmap(d.txMem)
	}
	if d.fillMem != nil {
		unix.Munmap(d.fillMem)
	}
	if d.compMem != nil {
		unix.Munmap(d.compMem)
	}
	if d.umem != nil {
		unix.Munmap(d.umem)
	}
	if d.fd >= 0 {
		unix.Close(d.fd)
		d.fd = -1
	}
}

// --- Syscall helpers ---

func setsockoptUmemReg(fd int, reg *unix.XDPUmemReg) error {
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT,
		uintptr(fd), unix.SOL_XDP, unix.XDP_UMEM_REG,
		uintptr(unsafe.Pointer(reg)),
		unsafe.Sizeof(*reg), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func setsockoptUint32(fd int, opt int, val uint32) error {
	return unix.SetsockoptInt(fd, unix.SOL_XDP, opt, int(val))
}

func getsockoptMmapOffsets(fd int) (*unix.XDPMmapOffsets, error) {
	var off unix.XDPMmapOffsets
	size := uint32(unsafe.Sizeof(off))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), unix.SOL_XDP, unix.XDP_MMAP_OFFSETS,
		uintptr(unsafe.Pointer(&off)),
		uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, errno
	}
	return &off, nil
}

func getsockoptStatistics(fd int) (unix.XDPStatistics, error) {
	var stats unix.XDPStatistics
	size := uint32(unsafe.Sizeof(stats))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT,
		uintptr(fd), unix.SOL_XDP, unix.XDP_STATISTICS,
		uintptr(unsafe.Pointer(&stats)),
		uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return stats, errno
	}
	return stats, nil
}

func mmapRing(fd int, pgoff uint64, off unix.XDPRingOffset, size uint32) ([]byte, error) {
	// Total mmap size: desc array offset + size * max_entry_size (16 bytes for XDPDesc).
	totalSize := off.Desc + uint64(size)*16
	return unix.Mmap(fd, int64(pgoff), int(totalSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
}
