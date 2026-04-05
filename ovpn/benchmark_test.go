package ovpn

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/KarpelesLab/pktkit"
)

// setupDataPeer creates a Peer with keys and options ready for data channel
// encrypt/decrypt benchmarking. cipher is "AES-256-GCM" or "AES-128-CBC".
func setupDataPeer(b *testing.B, cipher string) *Peer {
	b.Helper()

	opt := NewOptions()
	if err := opt.ParseCipher(cipher); err != nil {
		b.Fatal(err)
	}
	if opt.CipherBlock == GCM {
		opt.Auth = 0 // GCM doesn't use separate HMAC
	}
	opt.Compression = "lzo" // adds 0xfa compression byte
	if err := opt.Prepare(); err != nil {
		b.Fatal(err)
	}

	// Generate random key material
	keyMaterial := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		b.Fatal(err)
	}
	keys := NewPeerKeys(keyMaterial)

	p := &Peer{
		opts:         opt,
		keys:         keys,
		replayWindow: newWindow(),
		layer:        3, // tun
		c:            &discardSender{},
	}

	// Set a no-op L3 packet handler
	p.onL3Packet = func(pkt pktkit.Packet) {}

	return p
}

func BenchmarkDataEncryptGCM(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			p := setupDataPeer(b, "AES-256-GCM")
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if err := p.SendData(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDataDecryptGCM(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			p := setupDataPeer(b, "AES-256-GCM")
			payload := make([]byte, size)

			// Encrypt a batch of packets to decrypt
			packets := make([][]byte, 1024)
			for i := range packets {
				// Capture what SendData would send
				var captured []byte
				origSend := p.c
				p.c = &captureSender{captured: &captured}
				if err := p.SendData(payload); err != nil {
					b.Fatal(err)
				}
				packets[i] = captured
				p.c = origSend
			}

			// Fresh peer for decrypting (swap encrypt/decrypt keys)
			dp := setupDataPeer(b, "AES-256-GCM")
			// Swap keys: sender's encrypt = receiver's decrypt
			dp.keys.CipherDecrypt, dp.keys.CipherEncrypt = p.keys.CipherEncrypt, p.keys.CipherDecrypt
			dp.keys.HmacDecrypt, dp.keys.HmacEncrypt = p.keys.HmacEncrypt, p.keys.HmacDecrypt

			b.SetBytes(int64(size))
			b.ResetTimer()
			idx := 0
			for b.Loop() {
				pkt := make([]byte, len(packets[idx%len(packets)]))
				copy(pkt, packets[idx%len(packets)])
				if err := dp.handleData(pkt); err != nil {
					b.Fatal(err)
				}
				idx++
			}
		})
	}
}

func BenchmarkDataEncryptCBC(b *testing.B) {
	for _, size := range []int{64, 512, 1420} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			p := setupDataPeer(b, "AES-128-CBC")
			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				if err := p.SendData(payload); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// captureSender captures the last sent packet for benchmarking.
type captureSender struct {
	captured *[]byte
}

// discardSender discards all sent packets.
type discardSender struct{}

func (d *discardSender) Send(pkt []byte) error { return nil }
func (d *discardSender) SetPeer(p *Peer)       {}
func (d *discardSender) Close()                {}

func (c *captureSender) Send(pkt []byte) error {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	*c.captured = cp
	return nil
}

func (c *captureSender) SetPeer(p *Peer) {}
func (c *captureSender) Close()          {}

func BenchmarkReplayWindow(b *testing.B) {
	b.Run("sequential", func(b *testing.B) {
		w := newWindow()
		id := uint32(0)
		for b.Loop() {
			w.check(id)
			id++
		}
	})
	b.Run("in-window", func(b *testing.B) {
		w := newWindow()
		for i := uint32(0); i < replayWindowSize; i++ {
			w.check(i)
		}
		b.ResetTimer()
		id := uint32(0)
		for b.Loop() {
			w.check(id % replayWindowSize)
			id++
		}
	})
}

func BenchmarkPRF10(b *testing.B) {
	for _, size := range []int{48, 128, 256} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			result := make([]byte, size)
			secret := make([]byte, 48)
			label := []byte("key expansion")
			seed := make([]byte, 64)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				prf10(result, secret, label, seed)
			}
		})
	}
}

func BenchmarkPRF12(b *testing.B) {
	prf := prf12(sha256.New)
	for _, size := range []int{48, 128, 256} {
		b.Run(fmt.Sprintf("%dB", size), func(b *testing.B) {
			result := make([]byte, size)
			secret := make([]byte, 48)
			label := []byte("key expansion")
			seed := make([]byte, 64)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				prf(result, secret, label, seed)
			}
		})
	}
}

func BenchmarkOptionsParse(b *testing.B) {
	optStr := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	b.ResetTimer()
	for b.Loop() {
		o := NewOptions()
		if err := o.Parse(optStr); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOptionsString(b *testing.B) {
	o := NewOptions()
	o.Parse("V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server")
	b.ResetTimer()
	for b.Loop() {
		_ = o.String()
	}
}

func BenchmarkOptionsRoundtrip(b *testing.B) {
	optStr := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto TCPv4_SERVER,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	b.ResetTimer()
	for b.Loop() {
		o := NewOptions()
		o.Parse(optStr)
		_ = o.String()
	}
}
