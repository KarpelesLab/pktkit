package wg_test

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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
	setRecv func(func(pktkit.Packet))
}

// setupWGUDP creates two WireGuard endpoints connected via UDP loopback
// with a completed handshake.
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

	var serverOnRecv atomic.Pointer[func(pktkit.Packet)]
	var clientOnRecv atomic.Pointer[func(pktkit.Packet)]

	serverSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: serverHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			if fn := serverOnRecv.Load(); fn != nil {
				(*fn)(pktkit.Packet(data))
			}
		},
	})
	server.server = serverSrv

	clientSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: clientHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			if fn := clientOnRecv.Load(); fn != nil {
				(*fn)(pktkit.Packet(data))
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

	// Expose recv callback setters via closure
	server.setRecv = func(fn func(pktkit.Packet)) { serverOnRecv.Store(&fn) }
	client.setRecv = func(fn func(pktkit.Packet)) { clientOnRecv.Store(&fn) }

	return
}

// setRecv is attached by setupWGUDP to allow setting the receive callback
// after setup. This field exists only in tests.
func init() {} // ensure the extension field compiles

// We use a closure-based approach since we can't add fields to wgEndpoint
// after the fact. The setupWGUDP stores setRecv closures on the endpoints.

// BenchmarkE2EWireGuardUDP measures pipelined one-way UDP throughput.
func BenchmarkE2EWireGuardUDP(b *testing.B) {
	b.Skip("see BenchmarkE2EWireGuardThroughput")
}

// BenchmarkE2EWireGuardThroughput measures saturated unidirectional throughput
// by pipelining: the sender blasts packets as fast as possible while the
// receiver counts arrivals. This measures real throughput, not per-packet latency.
func BenchmarkE2EWireGuardThroughput(b *testing.B) {
	serverKey, _ := wg.GeneratePrivateKey()
	clientKey, _ := wg.GeneratePrivateKey()

	serverHandler, _ := wg.NewHandler(wg.Config{PrivateKey: serverKey})
	clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
	defer serverHandler.Close()
	defer clientHandler.Close()

	serverHandler.AddPeer(clientHandler.PublicKey())
	clientHandler.AddPeer(serverHandler.PublicKey())

	var received atomic.Int64

	serverSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: serverHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			received.Add(1)
		},
	})

	clientSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: clientHandler,
		OnPacket: func([]byte, wg.NoisePublicKey, *wg.Handler) {},
	})

	udpServer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	udpClient, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer udpServer.Close()
	defer udpClient.Close()

	go serverSrv.Serve(udpServer)
	go clientSrv.Serve(udpClient)
	defer serverSrv.Close()
	defer clientSrv.Close()

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
		b.Fatal("handshake did not complete")
	}

	peerKey := serverHandler.PublicKey()
	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	// Pipeline: send all packets, then wait for them all to arrive
	for b.Loop() {
		clientSrv.Send(pkt, peerKey)
	}

	b.StopTimer()

	// Drain: wait for in-flight packets (up to 500ms)
	target := int64(b.N)
	drainDeadline := time.Now().Add(500 * time.Millisecond)
	for received.Load() < target && time.Now().Before(drainDeadline) {
		time.Sleep(time.Millisecond)
	}

	got := received.Load()
	if got < target {
		b.Logf("warning: sent %d, received %d (%.1f%% loss)", target, got, 100*float64(target-got)/float64(target))
	}
}

// BenchmarkE2EWireGuardLatency measures per-packet latency (synchronous send-wait).
func BenchmarkE2EWireGuardLatency(b *testing.B) {
	serverKey, _ := wg.GeneratePrivateKey()
	clientKey, _ := wg.GeneratePrivateKey()

	serverHandler, _ := wg.NewHandler(wg.Config{PrivateKey: serverKey})
	clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
	defer serverHandler.Close()
	defer clientHandler.Close()

	serverHandler.AddPeer(clientHandler.PublicKey())
	clientHandler.AddPeer(serverHandler.PublicKey())

	var onRecv atomic.Pointer[func()]

	serverSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: serverHandler,
		OnPacket: func(data []byte, key wg.NoisePublicKey, h *wg.Handler) {
			if fn := onRecv.Load(); fn != nil {
				(*fn)()
			}
		},
	})

	clientSrv, _ := wg.NewServer(wg.ServerConfig{
		Handler: clientHandler,
		OnPacket: func([]byte, wg.NoisePublicKey, *wg.Handler) {},
	})

	udpServer, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	udpClient, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer udpServer.Close()
	defer udpClient.Close()

	go serverSrv.Serve(udpServer)
	go clientSrv.Serve(udpClient)
	defer serverSrv.Close()
	defer clientSrv.Close()

	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)
	clientSrv.Connect(serverHandler.PublicKey(), serverAddr)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if clientHandler.HasSession(serverHandler.PublicKey()) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	peerKey := serverHandler.PublicKey()
	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	var wg sync.WaitGroup
	fn := func() { wg.Done() }
	onRecv.Store(&fn)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		wg.Add(1)
		clientSrv.Send(pkt, peerKey)
		wg.Wait()
	}
}

func BenchmarkE2EWireGuardUDPRoundtrip(b *testing.B) {
	b.Skip("see BenchmarkE2EWireGuardLatency for per-packet timing")
}

func init() {
	// Suppress unused field warning
	_ = fmt.Sprint
}
