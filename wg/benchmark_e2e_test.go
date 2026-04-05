package wg_test

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/wg"
)

// makeIPv4UDP builds a minimal valid IPv4/UDP packet with the given payload size.
func makeIPv4UDP(src, dst netip.Addr, payloadSize int) []byte {
	udpLen := 8 + payloadSize
	totalLen := 20 + udpLen
	pkt := make([]byte, totalLen)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = 64
	pkt[9] = 17
	s := src.As4()
	d := dst.As4()
	copy(pkt[12:16], s[:])
	copy(pkt[16:20], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], 12345)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	return pkt
}

// wgEndpoint holds one side of a WireGuard UDP tunnel.
type wgEndpoint struct {
	handler *wg.Handler
	server  *wg.Server
	conn    net.PacketConn
	peerKey wg.NoisePublicKey
	onRecv  func(pktkit.Packet) // called on decrypted packet
}

// setupWGUDP creates two WireGuard endpoints connected via UDP loopback
// with a completed handshake. Returns (client, server, cleanup).
func setupWGUDP(tb testing.TB) (client, server *wgEndpoint, cleanup func()) {
	tb.Helper()

	serverKey, _ := wg.GeneratePrivateKey()
	clientKey, _ := wg.GeneratePrivateKey()

	serverHandler, _ := wg.NewHandler(wg.Config{PrivateKey: serverKey})
	clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})

	serverHandler.AddPeer(clientHandler.PublicKey())
	clientHandler.AddPeer(serverHandler.PublicKey())

	server = &wgEndpoint{handler: serverHandler, peerKey: clientHandler.PublicKey()}
	client = &wgEndpoint{handler: clientHandler, peerKey: serverHandler.PublicKey()}

	serverSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: serverHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			if server.onRecv != nil {
				server.onRecv(pktkit.Packet(data))
			}
		},
	})
	server.server = serverSrv

	clientSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: clientHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			if client.onRecv != nil {
				client.onRecv(pktkit.Packet(data))
			}
		},
	})
	client.server = clientSrv

	udpServer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	udpClient, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	server.conn = udpServer
	client.conn = udpClient

	go serverSrv.Serve(udpServer)
	go clientSrv.Serve(udpClient)

	// Handshake
	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)
	clientSrv.Connect(serverHandler.PublicKey(), serverAddr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if clientHandler.HasSession(serverHandler.PublicKey()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !clientHandler.HasSession(serverHandler.PublicKey()) {
		tb.Fatal("WireGuard handshake did not complete")
	}

	cleanup = func() {
		clientSrv.Close()
		serverSrv.Close()
		udpClient.Close()
		udpServer.Close()
		clientHandler.Close()
		serverHandler.Close()
	}
	return
}

// BenchmarkE2EWireGuardUDP measures one-way UDP throughput:
// packet → WG encrypt → UDP loopback → WG decrypt → callback
func BenchmarkE2EWireGuardUDP(b *testing.B) {
	client, server, cleanup := setupWGUDP(b)
	defer cleanup()

	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	var wg sync.WaitGroup
	server.onRecv = func(p pktkit.Packet) {
		wg.Done()
	}

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		wg.Add(1)
		client.server.Send(pkt, client.peerKey)
		wg.Wait()
	}
}

// BenchmarkE2EWireGuardUDPRoundtrip measures echo throughput over UDP:
// send → encrypt → UDP → decrypt → echo → encrypt → UDP → decrypt → receive
func BenchmarkE2EWireGuardUDPRoundtrip(b *testing.B) {
	client, server, cleanup := setupWGUDP(b)
	defer cleanup()

	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	// Server echoes back
	server.onRecv = func(p pktkit.Packet) {
		reply := make([]byte, len(p))
		copy(reply, p)
		copy(reply[12:16], p[16:20])
		copy(reply[16:20], p[12:16])
		binary.BigEndian.PutUint16(reply[10:12], 0)
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(reply[i : i+2]))
		}
		for sum > 0xffff {
			sum = (sum >> 16) + (sum & 0xffff)
		}
		binary.BigEndian.PutUint16(reply[10:12], ^uint16(sum))
		server.server.Send(reply, server.peerKey)
	}

	var wg sync.WaitGroup
	client.onRecv = func(p pktkit.Packet) {
		wg.Done()
	}

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		wg.Add(1)
		client.server.Send(pkt, client.peerKey)
		wg.Wait()
	}
}
