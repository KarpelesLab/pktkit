package vtcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"
)

// Common MSS values indexed for 3-bit encoding in the SYN cookie.
var mssTable = [8]uint16{536, 1200, 1360, 1440, 1452, 1460, 4312, 8960}

const (
	// cookieCounterPeriod is how often the time counter increments.
	// 5 bits → 32 values → ~34 minutes of validity at 64s per tick.
	cookieCounterPeriod = 64 // seconds

	// cookieSecretRotation is how often the HMAC secret is rotated.
	cookieSecretRotation = 60 * time.Second
)

// SYNCookies generates and validates SYN cookies for TCP SYN flood protection.
// When a listener's accept queue is full, SYN cookies allow handshakes to
// complete without allocating any per-connection state until the final ACK.
//
// The tradeoff is that SYN-cookie-established connections do not negotiate
// window scaling, SACK, or timestamps (there aren't enough bits in the
// 32-bit ISS to encode these options). This matches Linux's behavior.
type SYNCookies struct {
	mu         sync.Mutex
	secret     [32]byte
	prev       [32]byte
	lastRotate time.Time
}

// NewSYNCookies creates a new SYN cookie engine with a random secret.
func NewSYNCookies() *SYNCookies {
	sc := &SYNCookies{lastRotate: time.Now()}
	rand.Read(sc.secret[:])
	rand.Read(sc.prev[:])
	return sc
}

// rotateIfNeeded rotates the HMAC secret if enough time has passed.
// Must be called with sc.mu held.
func (sc *SYNCookies) rotateIfNeeded() {
	if time.Since(sc.lastRotate) < cookieSecretRotation {
		return
	}
	sc.prev = sc.secret
	rand.Read(sc.secret[:])
	sc.lastRotate = time.Now()
}

// GenerateSYNACK builds a SYN-ACK segment using a SYN cookie as the ISS.
// No connection state is allocated. The caller is responsible for wrapping
// the returned segment in an IP packet and sending it.
func (sc *SYNCookies) GenerateSYNACK(syn Segment, localPort, mss uint16) Segment {
	sc.mu.Lock()
	sc.rotateIfNeeded()
	secret := sc.secret
	sc.mu.Unlock()

	counter := uint32(time.Now().Unix()/cookieCounterPeriod) & 0x1F
	mssIdx := closestMSSIndex(mss)
	cookie := computeCookie(secret, syn.SrcPort, syn.DstPort, localPort, syn.Seq, counter, mssIdx)

	return Segment{
		SrcPort: localPort,
		DstPort: syn.SrcPort,
		Seq:     cookie,
		Ack:     syn.Seq + 1,
		Flags:   FlagSYN | FlagACK,
		Window:  65535,
		Options: []Option{MSSOption(mss)},
	}
}

// ValidateACK checks whether an incoming ACK segment completes a SYN-cookie
// handshake. If valid, returns the negotiated MSS and the remote's initial
// sequence number (seg.Seq - 1). The caller should then create a Conn via
// AcceptCookie.
func (sc *SYNCookies) ValidateACK(seg Segment, localPort uint16) (mss uint16, remoteISN uint32, ok bool) {
	if !seg.HasFlag(FlagACK) {
		return 0, 0, false
	}

	cookie := seg.Ack - 1
	counter := cookie & 0x1F
	mssIdx := (cookie >> 5) & 0x07
	remoteISN = seg.Seq - 1 // the remote's original SYN Seq

	sc.mu.Lock()
	sc.rotateIfNeeded()
	secrets := [2][32]byte{sc.secret, sc.prev}
	sc.mu.Unlock()

	now := uint32(time.Now().Unix()/cookieCounterPeriod) & 0x1F

	for _, secret := range secrets {
		// Allow current counter and one previous tick (handles boundary crossing).
		for delta := uint32(0); delta <= 1; delta++ {
			checkCounter := (now - delta) & 0x1F
			if checkCounter != counter {
				continue
			}
			candidate := computeCookie(secret, seg.SrcPort, seg.DstPort, localPort, remoteISN, checkCounter, uint8(mssIdx))
			if candidate == cookie {
				return mssTable[mssIdx], remoteISN, true
			}
		}
	}
	return 0, 0, false
}

// computeCookie generates the 32-bit SYN cookie value.
//
// Layout:
//
//	Bits 31-8  (24 bits): truncated HMAC
//	Bits  7-5  ( 3 bits): MSS table index
//	Bits  4-0  ( 5 bits): time counter
func computeCookie(secret [32]byte, srcPort, dstPort, localPort uint16, remoteISN, counter uint32, mssIdx uint8) uint32 {
	var buf [14]byte
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], localPort)
	binary.BigEndian.PutUint32(buf[6:10], remoteISN)
	binary.BigEndian.PutUint32(buf[10:14], counter)

	mac := hmac.New(sha256.New, secret[:])
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	hash24 := (uint32(sum[0]) << 16) | (uint32(sum[1]) << 8) | uint32(sum[2])
	return (hash24 << 8) | (uint32(mssIdx&0x07) << 5) | (counter & 0x1F)
}

// closestMSSIndex returns the MSS table index closest to (but not exceeding) mss.
func closestMSSIndex(mss uint16) uint8 {
	best := uint8(0)
	for i, v := range mssTable {
		if v <= mss {
			best = uint8(i)
		}
	}
	return best
}
