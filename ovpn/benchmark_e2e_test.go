package ovpn

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"

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

// ovpnEndpoint holds one side of an OpenVPN UDP data channel.
type ovpnEndpoint struct {
	peer   *Peer
	conn   *net.UDPConn
	remote *net.UDPAddr
	onRecv func(pktkit.Packet)
}

// readLoop reads encrypted packets from UDP and decrypts them.
func (e *ovpnEndpoint) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, _, err := e.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		// Copy because handleData modifies in-place
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		e.peer.handleData(pkt)
	}
}

// setupOVPNUDP creates two pre-keyed OpenVPN GCM peers connected via UDP loopback.
// Returns (client, server, cleanup).
func setupOVPNUDP(tb testing.TB) (client, server *ovpnEndpoint, cleanup func()) {
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

	// Create UDP endpoints
	udpClient, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	udpServer, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})

	clientAddr := udpClient.LocalAddr().(*net.UDPAddr)
	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)

	// Client peer sends encrypted packets to server via UDP
	clientPeer := &Peer{
		c:            &udpSender{conn: udpClient, remote: serverAddr},
		opts:         makeOpts(),
		keys:         clientKeys,
		replayWindow: newWindow(),
		layer:        3,
	}
	clientPeer.onL3Packet = func(pkt pktkit.Packet) {}

	// Server peer sends encrypted packets to client via UDP
	serverPeer := &Peer{
		c:            &udpSender{conn: udpServer, remote: clientAddr},
		opts:         makeOpts(),
		keys:         serverKeys,
		replayWindow: newWindow(),
		layer:        3,
	}
	serverPeer.onL3Packet = func(pkt pktkit.Packet) {}

	client = &ovpnEndpoint{peer: clientPeer, conn: udpClient, remote: serverAddr}
	server = &ovpnEndpoint{peer: serverPeer, conn: udpServer, remote: clientAddr}

	// Wire up L3 delivery
	serverPeer.onL3Packet = func(pkt pktkit.Packet) {
		if server.onRecv != nil {
			server.onRecv(pkt)
		}
	}
	clientPeer.onL3Packet = func(pkt pktkit.Packet) {
		if client.onRecv != nil {
			client.onRecv(pkt)
		}
	}

	// Start read loops
	go client.readLoop()
	go server.readLoop()

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

// BenchmarkE2EOpenVPNUDP measures one-way UDP throughput:
// packet → GCM encrypt → UDP loopback → GCM decrypt → callback
func BenchmarkE2EOpenVPNUDP(b *testing.B) {
	client, server, cleanup := setupOVPNUDP(b)
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
		client.peer.SendData(pkt)
		wg.Wait()
	}
}

// BenchmarkE2EOpenVPNUDPRoundtrip measures echo throughput over UDP:
// send → encrypt → UDP → decrypt → echo → encrypt → UDP → decrypt → receive
func BenchmarkE2EOpenVPNUDPRoundtrip(b *testing.B) {
	client, server, cleanup := setupOVPNUDP(b)
	defer cleanup()

	pkt := makeIPv4UDP(
		netip.MustParseAddr("10.0.0.2"),
		netip.MustParseAddr("10.0.0.1"),
		1372,
	)

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
		server.peer.SendData(reply)
	}

	var wg sync.WaitGroup
	client.onRecv = func(p pktkit.Packet) {
		wg.Done()
	}

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()

	for b.Loop() {
		wg.Add(1)
		client.peer.SendData(pkt)
		wg.Wait()
	}
}
