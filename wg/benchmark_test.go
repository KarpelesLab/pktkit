package wg

import (
	"fmt"
	"net"
	"testing"
)

func setupHandshakePair(b *testing.B) (client, server *Handler, clientPub, serverPub NoisePublicKey) {
	b.Helper()
	server, err := NewHandler(Config{})
	if err != nil {
		b.Fatal(err)
	}
	client, err = NewHandler(Config{})
	if err != nil {
		b.Fatal(err)
	}
	serverPub = server.PublicKey()
	clientPub = client.PublicKey()
	server.AddPeer(clientPub)
	client.AddPeer(serverPub)
	return
}

func doHandshake(b *testing.B, client, server *Handler, serverPub NoisePublicKey) {
	b.Helper()
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

	init, err := client.InitiateHandshake(serverPub)
	if err != nil {
		b.Fatal(err)
	}
	resp, err := server.ProcessPacket(init, addr)
	if err != nil {
		b.Fatal(err)
	}
	result, err := client.ProcessPacket(resp.Response, addr)
	if err != nil {
		b.Fatal(err)
	}
	// Send the keepalive back to server to confirm session
	_, err = server.ProcessPacket(result.Response, addr)
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for b.Loop() {
		_, err := GeneratePrivateKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHandshakeFull(b *testing.B) {
	for b.Loop() {
		client, server, _, serverPub := setupHandshakePair(b)
		doHandshake(b, client, server, serverPub)
		client.Close()
		server.Close()
	}
}

func BenchmarkHandshakeInitiation(b *testing.B) {
	client, server, _, serverPub := setupHandshakePair(b)
	defer client.Close()
	defer server.Close()

	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	b.ResetTimer()
	for b.Loop() {
		init, err := client.InitiateHandshake(serverPub)
		if err != nil {
			b.Fatal(err)
		}
		_, err = server.ProcessPacket(init, addr)
		if err != nil {
			b.Fatal(err)
		}
		// Cleanup handshake state to allow next iteration
		server.Maintenance()
		client.Maintenance()
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for _, size := range []int{0, 64, 128, 512, 1420} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			client, server, _, serverPub := setupHandshakePair(b)
			defer client.Close()
			defer server.Close()
			doHandshake(b, client, server, serverPub)

			payload := make([]byte, size)
			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				_, err := client.Encrypt(payload, serverPub)
				if err == ErrRekeyRequired {
					continue
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for _, size := range []int{0, 64, 128, 512, 1420} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			client, server, _, serverPub := setupHandshakePair(b)
			defer client.Close()
			defer server.Close()
			doHandshake(b, client, server, serverPub)

			payload := make([]byte, size)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				// Each packet must be unique (sequential counter) to avoid replay detection.
				pkt, err := client.Encrypt(payload, serverPub)
				if err == ErrRekeyRequired {
					err = nil
				}
				if err != nil {
					b.Fatal(err)
				}
				_, err = server.ProcessPacket(pkt, addr)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkEncryptDecrypt(b *testing.B) {
	for _, size := range []int{0, 64, 1420} {
		b.Run(sizeLabel(size), func(b *testing.B) {
			client, server, _, serverPub := setupHandshakePair(b)
			defer client.Close()
			defer server.Close()
			doHandshake(b, client, server, serverPub)

			payload := make([]byte, size)
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}

			b.SetBytes(int64(size))
			b.ResetTimer()
			for b.Loop() {
				enc, err := client.Encrypt(payload, serverPub)
				if err == ErrRekeyRequired {
					err = nil
				}
				if err != nil {
					b.Fatal(err)
				}
				_, err = server.ProcessPacket(enc, addr)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkReplayFilter(b *testing.B) {
	b.Run("sequential", func(b *testing.B) {
		var sw slidingWindow
		sw.Reset()
		counter := uint64(0)
		for b.Loop() {
			sw.CheckReplay(counter)
			counter++
		}
	})
	b.Run("in-window", func(b *testing.B) {
		var sw slidingWindow
		sw.Reset()
		// Fill window
		for i := uint64(0); i < WindowSize; i++ {
			sw.CheckReplay(i)
		}
		b.ResetTimer()
		// Check existing entries (replay detection)
		counter := uint64(0)
		for b.Loop() {
			sw.CheckReplay(counter % WindowSize)
			counter++
		}
	})
}

func BenchmarkPeerLookup(b *testing.B) {
	handler, err := NewHandler(Config{})
	if err != nil {
		b.Fatal(err)
	}
	defer handler.Close()

	var keys []NoisePublicKey
	for i := 0; i < 100; i++ {
		pk, _ := GeneratePrivateKey()
		pub := pk.PublicKey()
		handler.AddPeer(pub)
		keys = append(keys, pub)
	}

	b.ResetTimer()
	for b.Loop() {
		handler.IsAuthorizedPeer(keys[0])
	}
}

func sizeLabel(n int) string {
	if n == 0 {
		return "keepalive"
	}
	return fmt.Sprintf("%dB", n)
}
