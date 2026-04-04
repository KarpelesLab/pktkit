package nat

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const (
	defragTimeout     = 30 * time.Second
	defragMaxEntries  = 256
	defragCleanupFreq = 5 * time.Second
)

type fragKey struct {
	srcIP  [4]byte
	dstIP  [4]byte
	id     uint16
	proto  uint8
}

type fragEntry struct {
	frags   []fragData
	created time.Time
	total   int  // total length if last fragment seen, else -1
}

type fragData struct {
	offset int    // byte offset in original datagram
	data   []byte // fragment payload (after IP header)
	mf     bool   // more fragments flag
	ihl    int    // IP header length of this fragment
	hdr    []byte // IP header of first fragment (offset=0)
}

// Defragger reassembles fragmented IPv4 packets.
type Defragger struct {
	mu      sync.Mutex
	entries map[fragKey]*fragEntry
	done    chan struct{}
}

// EnableDefrag activates IP defragmentation on the NAT.
func (n *NAT) EnableDefrag() {
	d := newDefragger()
	if old := n.defragger.Swap(d); old != nil {
		old.Close()
	}
}

func newDefragger() *Defragger {
	d := &Defragger{
		entries: make(map[fragKey]*fragEntry),
		done:    make(chan struct{}),
	}
	go d.cleanup()
	return d
}

// Close stops the defragger cleanup goroutine.
func (d *Defragger) Close() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

// Process handles an IPv4 packet. If it's not fragmented, returns it as-is.
// If fragmented, buffers it and returns nil until all fragments arrive,
// then returns the reassembled packet.
func (d *Defragger) Process(pkt pktkit.Packet) pktkit.Packet {
	if len(pkt) < 20 {
		return pkt
	}

	// Check fragment flags and offset.
	flagsOff := binary.BigEndian.Uint16(pkt[6:8])
	mf := flagsOff&0x2000 != 0      // More Fragments flag
	fragOffset := int(flagsOff&0x1FFF) * 8 // fragment offset in bytes

	// Not fragmented — pass through.
	if !mf && fragOffset == 0 {
		return pkt
	}

	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl {
		return pkt
	}

	k := fragKey{
		srcIP: [4]byte(pkt[12:16]),
		dstIP: [4]byte(pkt[16:20]),
		id:    binary.BigEndian.Uint16(pkt[4:6]),
		proto: pkt[9],
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	e := d.entries[k]
	if e == nil {
		if len(d.entries) >= defragMaxEntries {
			return nil // too many concurrent reassemblies
		}
		e = &fragEntry{created: time.Now(), total: -1}
		d.entries[k] = e
	}

	payload := pkt[ihl:]
	fd := fragData{
		offset: fragOffset,
		data:   make([]byte, len(payload)),
		mf:     mf,
		ihl:    ihl,
	}
	copy(fd.data, payload)

	// Keep the IP header from the first fragment (offset 0).
	if fragOffset == 0 {
		fd.hdr = make([]byte, ihl)
		copy(fd.hdr, pkt[:ihl])
	}

	e.frags = append(e.frags, fd)

	// If this is the last fragment (MF=0), we know the total size.
	if !mf {
		e.total = fragOffset + len(payload)
	}

	// Check if we can reassemble.
	if e.total < 0 {
		return nil // don't know total size yet
	}

	// Enforce maximum reassembled size (65535 = max IPv4 packet payload).
	if e.total > 65535 {
		delete(d.entries, k)
		return nil
	}

	// Check coverage: all bytes from 0 to total must be covered.
	covered := make([]bool, e.total)
	var firstHdr []byte
	for _, f := range e.frags {
		end := f.offset + len(f.data)
		if end > e.total {
			end = e.total
		}
		for i := f.offset; i < end; i++ {
			if covered[i] {
				// Overlapping fragment detected — reject per RFC 5722 best practice.
				delete(d.entries, k)
				return nil
			}
			covered[i] = true
		}
		if f.hdr != nil {
			firstHdr = f.hdr
		}
	}
	for _, c := range covered {
		if !c {
			return nil // still missing fragments
		}
	}

	if firstHdr == nil {
		delete(d.entries, k)
		return nil
	}

	// Reassemble.
	reassembled := make([]byte, e.total)
	for _, f := range e.frags {
		copy(reassembled[f.offset:], f.data)
	}

	delete(d.entries, k)

	// Build the final packet with the first fragment's IP header.
	totalLen := len(firstHdr) + len(reassembled)
	result := make(pktkit.Packet, totalLen)
	copy(result, firstHdr)
	copy(result[len(firstHdr):], reassembled)

	// Fix IP header: clear MF flag, set offset to 0, update total length.
	binary.BigEndian.PutUint16(result[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(result[6:8], 0) // clear flags+offset

	// Recalculate IP checksum.
	binary.BigEndian.PutUint16(result[10:12], 0)
	binary.BigEndian.PutUint16(result[10:12], pktkit.Checksum(result[:len(firstHdr)]))

	return result
}

func (d *Defragger) cleanup() {
	ticker := time.NewTicker(defragCleanupFreq)
	defer ticker.Stop()
	for {
		select {
		case <-d.done:
			return
		case <-ticker.C:
		}
		now := time.Now()
		d.mu.Lock()
		for k, e := range d.entries {
			if now.Sub(e.created) > defragTimeout {
				delete(d.entries, k)
			}
		}
		d.mu.Unlock()
	}
}
