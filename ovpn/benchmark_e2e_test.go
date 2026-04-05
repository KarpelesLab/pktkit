package ovpn

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
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

// setupOVPNUDP creates two pre-keyed OpenVPN GCM peers connected via UDP loopback.
// onServerRecv is called for each decrypted packet arriving at the server side.
func setupOVPNUDP(tb testing.TB, onServerRecv func(pktkit.Packet)) (clientPeer *Peer, cleanup func()) {
	tb.Helper()

	keyMaterial := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, keyMaterial); err != nil {
		tb.Fatal(err)
	}

	clientKeys := NewPeerKeys(keyMaterial)
	serverKeys := &PeerKeys{
		CipherEncrypt: make([]byte, 64),
		HmacEncrypt:   make([]byte, 64),
		CipherDecrypt: make([]byte, 64),
		HmacDecrypt:   make([]byte, 64),
	}
	copy(serverKeys.CipherDecrypt, clientKeys.CipherEncrypt)
	copy(serverKeys.HmacDecrypt, clientKeys.HmacEncrypt)
	copy(serverKeys.CipherEncrypt, clientKeys.CipherDecrypt)
	copy(serverKeys.HmacEncrypt, clientKeys.HmacDecrypt)

	makeOpts := func() *Options {
		opt := &Options{
			CipherCrypto: AES,
			CipherSize:   256,
			CipherBlock:  GCM,
			Compression:  "lzo",
		}
		opt.Prepare()
		return opt
	}

	udpClient, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	udpServer, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})

	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)

	clientPeer = &Peer{
		c:            &udpSender{conn: udpClient, remote: serverAddr},
		opts:         makeOpts(),
		keys:         clientKeys,
		replayWindow: newWindow(),
		layer:        3,
	}
	clientPeer.onL3Packet = func(pkt pktkit.Packet) {}

	serverPeer := &Peer{
		c:            &udpSender{conn: udpServer, remote: udpClient.LocalAddr().(*net.UDPAddr)},
		opts:         makeOpts(),
		keys:         serverKeys,
		replayWindow: newWindow(),
		layer:        3,
	}
	serverPeer.onL3Packet = onServerRecv

	// Server read loop
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := udpServer.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			serverPeer.handleData(pkt)
		}
	}()

	cleanup = func() {
		udpClient.Close()
		udpServer.Close()
	}
	return
}

// udpSender sends raw bytes over UDP to a fixed remote address.
type udpSender struct {
	conn   *net.UDPConn
	remote *net.UDPAddr
}

func (u *udpSender) Send(pkt []byte) error {
	_, err := u.conn.WriteToUDP(pkt, u.remote)
	return err
}
func (u *udpSender) SetPeer(p *Peer) {}
func (u *udpSender) Close()          {}

// BenchmarkE2EOpenVPNThroughput measures saturated unidirectional throughput.
// The sender pipelines packets as fast as possible; the receiver counts arrivals.
func BenchmarkE2EOpenVPNThroughput(b *testing.B) {
	var received atomic.Int64

	client, cleanup := setupOVPNUDP(b, func(p pktkit.Packet) {
		received.Add(1)
	})
	defer cleanup()

	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		client.SendData(pkt)
	}

	b.StopTimer()

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

// BenchmarkE2EOpenVPNLatency measures per-packet latency (synchronous send-wait).
func BenchmarkE2EOpenVPNLatency(b *testing.B) {
	done := make(chan struct{}, 1)

	client, cleanup := setupOVPNUDP(b, func(p pktkit.Packet) {
		select {
		case done <- struct{}{}:
		default:
		}
	})
	defer cleanup()

	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

	// Warm up — ensure cipher is initialized
	client.SendData(pkt)
	select {
	case <-done:
	case <-time.After(time.Second):
		b.Fatal("warmup packet not received")
	}

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		client.SendData(pkt)
		<-done
	}
}
