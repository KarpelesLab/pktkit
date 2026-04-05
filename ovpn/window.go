package ovpn

import "sync"

const replayWindowSize = 2048 // bits

// window implements replay protection using a bitmap-based sliding window.
// It tracks which packet IDs have been seen to detect duplicates and
// replay attacks per RFC 6479.
type window struct {
	mu       sync.Mutex
	bitmap   [replayWindowSize / 64]uint64
	position uint64 // position at start of bitmap (multiple of 64)
	offset   uint64 // offset within bitmap array (ring buffer)
	init     bool
}

func newWindow() *window {
	return &window{}
}

// check returns true if the packet ID is new (not a replay).
// Returns false if the ID has already been seen or is too old.
func (w *window) check(id uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	counter := uint64(id)

	if !w.init {
		w.position = counter - (counter % 64)
		w.offset = 0
		w.init = true
		for i := range w.bitmap {
			w.bitmap[i] = 0
		}
	}

	// Too old
	if counter < w.position {
		return false
	}

	// Outside window — advance
	if counter >= w.position+replayWindowSize {
		diff := counter - (w.position + replayWindowSize) + 1
		if n := diff % 64; n != 0 {
			diff += 64 - n
		}

		w.position += diff

		if diff >= replayWindowSize {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
			w.offset = 0
		} else {
			wordShift := diff / 64
			bitmapWords := uint64(len(w.bitmap))
			newOffset := (w.offset + wordShift) % bitmapWords
			for i := uint64(0); i < wordShift; i++ {
				w.bitmap[(newOffset+bitmapWords-1-i)%bitmapWords] = 0
			}
			w.offset = newOffset
		}

		pos := counter - w.position
		wordIndex := (w.offset + pos/64) % uint64(len(w.bitmap))
		bitIndex := pos % 64
		w.bitmap[wordIndex] |= uint64(1) << bitIndex
		return true
	}

	// Within window — check bitmap
	pos := counter - w.position
	wordIndex := (w.offset + pos/64) % uint64(len(w.bitmap))
	bitIndex := pos % 64

	mask := uint64(1) << bitIndex
	if (w.bitmap[wordIndex] & mask) != 0 {
		return false // replay
	}

	w.bitmap[wordIndex] |= mask
	return true
}
