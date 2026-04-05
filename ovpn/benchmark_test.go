package ovpn

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

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
