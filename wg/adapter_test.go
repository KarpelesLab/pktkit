package wg_test

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
	"github.com/KarpelesLab/pktkit/wg"
)

// TestAdapterHub sets up two WireGuard adapters on a shared L2Hub. Each peer
// has a vclient behind it. We verify that one vclient can TCP-connect to the
// other through the WireGuard tunnel + hub.
func TestAdapterHub(t *testing.T) {
	hub := pktkit.NewL2Hub()

	// --- Adapter A (server side) ---
	adapterA, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: hub,
		Addr:      netip.MustParsePrefix("10.50.0.1/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapterA.Close()

	// --- Adapter B (client side) ---
	adapterB, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: hub,
		Addr:      netip.MustParsePrefix("10.50.0.1/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapterB.Close()

	// Authorize each other.
	adapterA.AddPeer(adapterB.PublicKey())
	adapterB.AddPeer(adapterA.PublicKey())

	// Start A on a UDP listener.
	udpA, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpA.Close()

	go adapterA.Serve(udpA)

	// Start B on a UDP listener.
	udpB, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpB.Close()

	go adapterB.Serve(udpB)

	// B initiates handshake to A.
	addrA := udpA.LocalAddr().(*net.UDPAddr)
	if err := adapterB.Connect(adapterA.PublicKey(), addrA); err != nil {
		t.Fatal(err)
	}

	// Wait for handshake to complete and peer plumbing to be set up.
	time.Sleep(200 * time.Millisecond)

	// --- Set up a vclient "server" behind adapter A ---
	srvClient := vclient.New()
	defer srvClient.Close()
	srvClient.SetIP(net.IPv4(10, 50, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 50, 0, 1))
	srvAdapter := pktkit.NewL2Adapter(srvClient, nil)
	defer srvAdapter.Close()
	hub.Connect(srvAdapter)

	tcpLn, err := srvClient.Listen("tcp", "0.0.0.0:8000")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("wg-hub-ok"))
			time.Sleep(10 * time.Millisecond)
			c.Close()
		}
	}()

	// --- Set up a vclient "client" behind adapter B ---
	cliClient := vclient.New()
	defer cliClient.Close()
	cliClient.SetIP(net.IPv4(10, 50, 0, 3), net.CIDRMask(24, 32), net.IPv4(10, 50, 0, 1))
	cliAdapter := pktkit.NewL2Adapter(cliClient, nil)
	defer cliAdapter.Close()
	hub.Connect(cliAdapter)

	// Try to reach the server.
	conn, err := cliClient.Dial("tcp", "10.50.0.2:8000")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if got := string(buf[:n]); got != "wg-hub-ok" {
		t.Errorf("got %q, want %q", got, "wg-hub-ok")
	}
}

// TestAdapterNamespace sets up a WireGuard adapter with a slirp namespace
// provider. Each peer gets an isolated namespace. We verify namespace
// creation and cleanup.
func TestAdapterNamespace(t *testing.T) {
	provider := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("172.30.0.1/24"),
	})
	defer provider.Close()

	serverAdapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: provider,
		Addr:      netip.MustParsePrefix("172.30.0.1/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer serverAdapter.Close()

	// Start server on UDP.
	udpServer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpServer.Close()

	go serverAdapter.Serve(udpServer)

	// Connect two clients — each should get its own namespace.
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

	// Wait for handshakes + namespace creation.
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
	// Get peer keys from the handler.
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
	hub := pktkit.NewL2Hub()

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: hub,
		Addr:      netip.MustParsePrefix("10.50.0.1/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()

	// Generate a peer key.
	peerKey, _ := wg.GeneratePrivateKey()
	pubKey := peerKey.PublicKey()

	adapter.AddPeer(pubKey)

	// Verify the adapter's handler knows about the peer.
	if !adapter.Handler().IsAuthorizedPeer(pubKey) {
		t.Error("peer should be authorized")
	}

	// Remove the peer.
	adapter.RemovePeer(pubKey)

	if adapter.Handler().IsAuthorizedPeer(pubKey) {
		t.Error("peer should no longer be authorized")
	}
}

// TestAdapterUnknownPeer verifies dynamic peer authorization via OnUnknownPeer.
func TestAdapterUnknownPeer(t *testing.T) {
	hub := pktkit.NewL2Hub()

	unknownCh := make(chan wg.NoisePublicKey, 1)

	adapter, err := wg.NewAdapter(wg.AdapterConfig{
		Connector: hub,
		Addr:      netip.MustParsePrefix("10.50.0.1/24"),
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

	// Create a client that is NOT pre-authorized.
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

	// Client tries to connect — should trigger OnUnknownPeer.
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

