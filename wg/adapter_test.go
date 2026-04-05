package wg_test

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
	"github.com/KarpelesLab/pktkit/wg"
)

// TestAdapterNamespace sets up a WireGuard adapter with a slirp namespace
// provider (L3Connector). Each peer gets an isolated NAT stack. We verify
// namespace creation and cleanup.
func TestAdapterNamespace(t *testing.T) {
	provider := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("172.30.0.1/24"),
	})
	defer provider.Close()

	serverAdapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverAdapter.Close()

	udpServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()

	go serverAdapter.Serve(udpServer)

	connectClient := func() (*wg.Server, net.PacketConn) {
		clientKey, _ := wg.GeneratePrivateKey()
		clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
		serverAdapter.AddPeer(clientHandler.PublicKey())
		clientHandler.AddPeer(serverAdapter.PublicKey())

		udpClient, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		clientServer, _ := wg.NewServer(wg.ServerConfig{
			Handler:  clientHandler,
			OnPacket: func([]byte, wg.NoisePublicKey, *wg.Handler) {},
		})
		go clientServer.Serve(udpClient)

		serverAddr := udpServer.LocalAddr().(*net.UDPAddr)
		clientServer.Connect(serverAdapter.PublicKey(), serverAddr)
		return clientServer, udpClient
	}

	c1, u1 := connectClient()
	defer u1.Close()
	defer c1.Close()

	c2, u2 := connectClient()
	defer u2.Close()
	defer c2.Close()

	for i := 0; i < 50; i++ {
		if len(provider.List()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	names := provider.List()
	if len(names) != 2 {
		t.Fatalf("expected 2 namespaces, got %d: %v", len(names), names)
	}
	t.Logf("namespaces: %v", names)

	// Remove one peer — its namespace should be cleaned up.
	peers := serverAdapter.Handler().Peers()
	if len(peers) < 2 {
		t.Fatalf("expected at least 2 peers, got %d", len(peers))
	}
	serverAdapter.RemovePeer(peers[0])

	names = provider.List()
	if len(names) != 1 {
		t.Errorf("expected 1 namespace after removal, got %d: %v", len(names), names)
	}
}

// TestAdapterPeerLifecycle verifies peer setup and removal.
func TestAdapterPeerLifecycle(t *testing.T) {
	provider := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.50.0.1/24"),
	})
	defer provider.Close()

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	peerKey, _ := wg.GeneratePrivateKey()
	pubKey := peerKey.PublicKey()

	adapter.AddPeer(pubKey)
	if !adapter.Handler().IsAuthorizedPeer(pubKey) {
		t.Error("peer should be authorized")
	}

	adapter.RemovePeer(pubKey)
	if adapter.Handler().IsAuthorizedPeer(pubKey) {
		t.Error("peer should no longer be authorized")
	}
}

// TestAdapterUnknownPeer verifies dynamic peer authorization via OnUnknownPeer.
func TestAdapterUnknownPeer(t *testing.T) {
	provider := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.50.0.1/24"),
	})
	defer provider.Close()

	unknownCh := make(chan wg.NoisePublicKey, 1)

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: provider,
		OnUnknownPeer: func(key wg.NoisePublicKey, addr *net.UDPAddr, packet []byte) {
			unknownCh <- key
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	udpA, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer udpA.Close()
	go adapter.Serve(udpA)

	clientKey, _ := wg.GeneratePrivateKey()
	clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
	defer clientHandler.Close()
	clientHandler.AddPeer(adapter.PublicKey())

	udpB, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	defer udpB.Close()

	clientServer, _ := wg.NewServer(wg.ServerConfig{
		Handler:  clientHandler,
		OnPacket: func([]byte, wg.NoisePublicKey, *wg.Handler) {},
	})
	defer clientServer.Close()
	go clientServer.Serve(udpB)

	serverAddr := udpA.LocalAddr().(*net.UDPAddr)
	clientServer.Connect(adapter.PublicKey(), serverAddr)

	select {
	case key := <-unknownCh:
		t.Logf("unknown peer callback fired: %s", key)
		if key != clientHandler.PublicKey() {
			t.Errorf("unexpected key: got %s, want %s", key, clientHandler.PublicKey())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for unknown peer callback")
	}
}

// TestWireGuardNATIsolation is the full end-to-end test: a WireGuard server
// connected to slirp NAT, with two clients using the SAME IP address, both
// accessing the internet simultaneously through isolated NAT namespaces.
//
// Topology:
//
//	Client 1 (vclient 10.0.0.2) ──WG tunnel──┐
//	                                           ├── WG Server ── slirp NAT ── Internet
//	Client 2 (vclient 10.0.0.2) ──WG tunnel──┘
//
// Each client gets its own slirp Stack via L3Connector, so even though
// they share the same IP, their NAT state is fully isolated.
func TestWireGuardNATIsolation(t *testing.T) {
	// --- Server side: WireGuard adapter + slirp NAT ---
	provider := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.0.0.1/24"),
	})
	defer provider.Close()

	serverAdapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: provider,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverAdapter.Close()

	udpServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()
	go serverAdapter.Serve(udpServer)

	serverAddr := udpServer.LocalAddr().(*net.UDPAddr)

	// --- Client factory: creates a WireGuard client with a vclient behind it ---
	// Both clients use the SAME IP (10.0.0.2), same gateway (10.0.0.1).
	type clientStack struct {
		vc      *vclient.Client
		wgSrv   *wg.Server
		udpConn net.PacketConn
	}

	makeClient := func() *clientStack {
		// WireGuard client handler.
		clientKey, _ := wg.GeneratePrivateKey()
		clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
		serverAdapter.AddPeer(clientHandler.PublicKey())
		clientHandler.AddPeer(serverAdapter.PublicKey())

		// vclient at 10.0.0.2, gateway 10.0.0.1.
		vc := vclient.New()
		vc.SetIP(net.IPv4(10, 0, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 0, 0, 1))
		vc.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})

		// The WireGuard client server delivers decrypted packets to vclient
		// and encrypts vclient's outgoing packets.
		wgSrv, _ := wg.NewServer(wg.ServerConfig{
			Handler: clientHandler,
			OnPacket: func(data []byte, _ wg.NoisePublicKey, _ *wg.Handler) {
				vc.Send(pktkit.Packet(data))
			},
		})

		// vclient's outgoing packets go through WireGuard.
		serverPubKey := serverAdapter.PublicKey()
		vc.SetHandler(func(pkt pktkit.Packet) error {
			return wgSrv.Send(pkt, serverPubKey)
		})

		udpConn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		go wgSrv.Serve(udpConn)

		// Initiate handshake to server.
		wgSrv.Connect(serverPubKey, serverAddr)

		return &clientStack{vc: vc, wgSrv: wgSrv, udpConn: udpConn}
	}

	client1 := makeClient()
	defer client1.vc.Close()
	defer client1.wgSrv.Close()
	defer client1.udpConn.Close()

	client2 := makeClient()
	defer client2.vc.Close()
	defer client2.wgSrv.Close()
	defer client2.udpConn.Close()

	// Wait for handshakes to complete.
	for i := 0; i < 50; i++ {
		if len(provider.List()) >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n := len(provider.List()); n != 2 {
		t.Fatalf("expected 2 namespaces, got %d", n)
	}

	// --- Both clients fetch from the internet simultaneously ---
	type result struct {
		id   int
		body string
		err  error
	}
	results := make(chan result, 2)

	fetch := func(id int, vc *vclient.Client) {
		hc := &http.Client{
			Transport: &http.Transport{DialContext: vc.DialContext},
			Timeout:   15 * time.Second,
		}
		resp, err := hc.Get("https://raw.githubusercontent.com/KarpelesLab/pktkit/refs/heads/master/README.md")
		if err != nil {
			results <- result{id: id, err: err}
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		results <- result{id: id, body: string(body)}
	}

	go fetch(1, client1.vc)
	go fetch(2, client2.vc)

	for i := 0; i < 2; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("client %d: %v", r.id, r.err)
			}
			if !strings.Contains(r.body, "pktkit") {
				t.Fatalf("client %d: response doesn't contain 'pktkit'", r.id)
			}
			t.Logf("client %d: fetched %d bytes", r.id, len(r.body))
		case <-time.After(30 * time.Second):
			t.Fatal("timeout waiting for HTTP responses")
		}
	}
}
