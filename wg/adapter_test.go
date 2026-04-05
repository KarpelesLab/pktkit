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
	"github.com/KarpelesLab/pktkit/nat"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
	"github.com/KarpelesLab/pktkit/wg"
)

// TestAdapterNATConnectL3 verifies that ConnectL3 on a nat.NAT creates
// namespace-isolated mappings and cleans them up on peer removal.
func TestAdapterNATConnectL3(t *testing.T) {
	n := nat.New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("100.64.0.2/24"),
	)
	defer n.Close()

	serverAdapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: n,
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

	time.Sleep(200 * time.Millisecond)

	// Both peers should be connected.
	peers := serverAdapter.Handler().Peers()
	if len(peers) < 2 {
		t.Fatalf("expected at least 2 peers, got %d", len(peers))
	}

	// Remove one — cleanup should not affect the other.
	serverAdapter.RemovePeer(peers[0])
	if serverAdapter.Handler().IsAuthorizedPeer(peers[0]) {
		t.Error("removed peer should no longer be authorized")
	}
	if !serverAdapter.Handler().IsAuthorizedPeer(peers[1]) {
		t.Error("remaining peer should still be authorized")
	}
}

// TestAdapterPeerLifecycle verifies peer setup and removal.
func TestAdapterPeerLifecycle(t *testing.T) {
	n := nat.New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("100.64.0.2/24"),
	)
	defer n.Close()

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: n,
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
	n := nat.New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("100.64.0.2/24"),
	)
	defer n.Close()

	unknownCh := make(chan wg.NoisePublicKey, 1)

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: n,
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

// TestWireGuardNATIsolation is the full end-to-end test with the topology:
//
//	Client 1 (vclient 10.0.0.2) ──WG──┐
//	                                    ├── WG Server ── NAT ── slirp ── Internet
//	Client 2 (vclient 10.0.0.2) ──WG──┘
//
// A single nat.NAT with namespace-aware connection tracking isolates both
// clients even though they share the same IP. The NAT's outside is wired
// to a slirp stack for real internet access.
func TestWireGuardNATIsolation(t *testing.T) {
	// --- Server side ---
	// slirp stack provides internet access on the outside.
	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("100.64.0.1/24"))

	// NAT: inside 10.0.0.1/24 (VPN clients), outside 100.64.0.2/24 (slirp LAN).
	n := nat.New(
		netip.MustParsePrefix("10.0.0.1/24"),
		netip.MustParsePrefix("100.64.0.2/24"),
	)
	defer n.Close()

	// Wire NAT outside ↔ slirp stack.
	pktkit.ConnectL3(n.Outside(), stack)

	// WireGuard adapter uses NAT as L3Connector — each peer gets a
	// namespace-isolated inside device on the same NAT instance.
	serverAdapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: n,
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

	// --- Client factory ---
	// Both clients use the SAME IP (10.0.0.2), same gateway (10.0.0.1).
	type clientStack struct {
		vc      *vclient.Client
		wgSrv   *wg.Server
		udpConn net.PacketConn
	}

	makeClient := func() *clientStack {
		clientKey, _ := wg.GeneratePrivateKey()
		clientHandler, _ := wg.NewHandler(wg.Config{PrivateKey: clientKey})
		serverAdapter.AddPeer(clientHandler.PublicKey())
		clientHandler.AddPeer(serverAdapter.PublicKey())

		vc := vclient.New()
		vc.SetIP(net.IPv4(10, 0, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 0, 0, 1))
		vc.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})

		wgSrv, _ := wg.NewServer(wg.ServerConfig{
			Handler: clientHandler,
			OnPacket: func(data []byte, _ wg.NoisePublicKey, _ *wg.Handler) {
				vc.Send(pktkit.Packet(data))
			},
		})

		serverPubKey := serverAdapter.PublicKey()
		vc.SetHandler(func(pkt pktkit.Packet) error {
			return wgSrv.Send(pkt, serverPubKey)
		})

		udpConn, _ := net.ListenPacket("udp4", "127.0.0.1:0")
		go wgSrv.Serve(udpConn)
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

	// Wait for handshakes.
	time.Sleep(200 * time.Millisecond)

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
