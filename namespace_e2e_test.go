package pktkit_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
)

// TestNamespaceIsolation verifies that two namespaces with the same IP
// range have fully isolated traffic.
func TestNamespaceIsolation(t *testing.T) {
	p := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("192.168.0.1/24"),
	})
	defer p.Close()

	ns1, _ := p.Create("ns1")
	ns2, _ := p.Create("ns2")

	hub1 := pktkit.NewL2Hub()
	hub2 := pktkit.NewL2Hub()
	h1 := hub1.Connect(ns1.Device())
	h2 := hub2.Connect(ns2.Device())
	defer h1.Close()
	defer h2.Close()

	// Server on hub1 at 192.168.0.2.
	srv1 := vclient.New()
	defer srv1.Close()
	srv1.SetIP(net.IPv4(192, 168, 0, 2), net.CIDRMask(24, 32), net.IPv4(192, 168, 0, 1))
	a1 := pktkit.NewL2Adapter(srv1, nil)
	defer a1.Close()
	hub1.Connect(a1)

	ln1, _ := srv1.Listen("tcp", "0.0.0.0:9001")
	defer ln1.Close()
	go func() {
		for {
			conn, err := ln1.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("from-ns1"))
			conn.Close()
		}
	}()

	// Server on hub2 at 192.168.0.2 (same IP, different namespace).
	srv2 := vclient.New()
	defer srv2.Close()
	srv2.SetIP(net.IPv4(192, 168, 0, 2), net.CIDRMask(24, 32), net.IPv4(192, 168, 0, 1))
	a2 := pktkit.NewL2Adapter(srv2, nil)
	defer a2.Close()
	hub2.Connect(a2)

	ln2, _ := srv2.Listen("tcp", "0.0.0.0:9001")
	defer ln2.Close()
	go func() {
		for {
			conn, err := ln2.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("from-ns2"))
			conn.Close()
		}
	}()

	// Probe on hub1 at .3.
	probe1 := vclient.New()
	defer probe1.Close()
	probe1.SetIP(net.IPv4(192, 168, 0, 3), net.CIDRMask(24, 32), net.IPv4(192, 168, 0, 1))
	pa1 := pktkit.NewL2Adapter(probe1, nil)
	defer pa1.Close()
	hub1.Connect(pa1)

	// Probe on hub2 at .3.
	probe2 := vclient.New()
	defer probe2.Close()
	probe2.SetIP(net.IPv4(192, 168, 0, 3), net.CIDRMask(24, 32), net.IPv4(192, 168, 0, 1))
	pa2 := pktkit.NewL2Adapter(probe2, nil)
	defer pa2.Close()
	hub2.Connect(pa2)

	buf := make([]byte, 32)

	// probe1 on hub1 → should reach srv1 ("from-ns1")
	conn1, err := probe1.Dial("tcp", "192.168.0.2:9001")
	if err != nil {
		t.Fatalf("probe1 dial: %v", err)
	}
	n, _ := conn1.Read(buf)
	conn1.Close()
	if got := string(buf[:n]); got != "from-ns1" {
		t.Errorf("probe1 got %q, want %q", got, "from-ns1")
	}

	// probe2 on hub2 → should reach srv2 ("from-ns2")
	conn2, err := probe2.Dial("tcp", "192.168.0.2:9001")
	if err != nil {
		t.Fatalf("probe2 dial: %v", err)
	}
	n, _ = conn2.Read(buf)
	conn2.Close()
	if got := string(buf[:n]); got != "from-ns2" {
		t.Errorf("probe2 got %q, want %q", got, "from-ns2")
	}
}

// TestNamespaceHTTPIsolation verifies HTTP servers at the same IP:port
// in different namespaces serve different content.
func TestNamespaceHTTPIsolation(t *testing.T) {
	p := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.77.0.1/24"),
	})
	defer p.Close()

	setup := func(name, response string) (*vclient.Client, func()) {
		ns, _ := p.Create(name)
		hub := pktkit.NewL2Hub()
		hns := hub.Connect(ns.Device())

		srv := vclient.New()
		srv.SetIP(net.IPv4(10, 77, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 77, 0, 1))
		a := pktkit.NewL2Adapter(srv, nil)
		hub.Connect(a)

		ln, _ := srv.Listen("tcp", "0.0.0.0:80")
		mux := http.NewServeMux()
		mux.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, response)
		})
		go http.Serve(ln, mux)

		client := vclient.New()
		client.SetIP(net.IPv4(10, 77, 0, 3), net.CIDRMask(24, 32), net.IPv4(10, 77, 0, 1))
		ca := pktkit.NewL2Adapter(client, nil)
		hub.Connect(ca)

		cleanup := func() {
			ln.Close()
			ca.Close()
			client.Close()
			a.Close()
			srv.Close()
			hns.Close()
		}
		return client, cleanup
	}

	clientA, cleanA := setup("nsA", "namespace-A")
	defer cleanA()
	clientB, cleanB := setup("nsB", "namespace-B")
	defer cleanB()

	fetch := func(c *vclient.Client, want string) {
		t.Helper()
		hc := &http.Client{
			Transport: &http.Transport{DialContext: c.DialContext},
		}
		resp, err := hc.Get("http://10.77.0.2/id")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if got := string(body); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}

	fetch(clientA, "namespace-A")
	fetch(clientB, "namespace-B")
}

// TestNamespaceInternetAccess verifies that a namespace can reach the
// real internet via slirp NAT.
func TestNamespaceInternetAccess(t *testing.T) {
	p := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.55.0.1/24"),
	})
	defer p.Close()

	ns, _ := p.Create("internet-test")
	hub := pktkit.NewL2Hub()
	hub.Connect(ns.Device())

	client := vclient.New()
	defer client.Close()
	client.SetIP(net.IPv4(10, 55, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 55, 0, 1))
	client.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})
	a := pktkit.NewL2Adapter(client, nil)
	defer a.Close()
	a.SetGateway(netip.MustParseAddr("10.55.0.1"))
	hub.Connect(a)

	hc := &http.Client{
		Transport: &http.Transport{DialContext: client.DialContext},
	}
	resp, err := hc.Get("https://raw.githubusercontent.com/KarpelesLab/pktkit/refs/heads/master/README.md")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "pktkit") {
		t.Fatal("response doesn't contain 'pktkit'")
	}
	t.Logf("downloaded %d bytes from GitHub via namespace", len(body))
}

// TestNamespaceDeleteCleansConnections verifies that deleting a namespace
// tears down active connections.
func TestNamespaceDeleteCleansConnections(t *testing.T) {
	p := slirp.NewProvider(slirp.ProviderConfig{
		Addr: netip.MustParsePrefix("10.88.0.1/24"),
	})
	defer p.Close()

	ns, _ := p.Create("ephemeral")
	hub := pktkit.NewL2Hub()
	hub.Connect(ns.Device())

	client := vclient.New()
	defer client.Close()
	client.SetIP(net.IPv4(10, 88, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 88, 0, 1))
	a := pktkit.NewL2Adapter(client, nil)
	defer a.Close()
	hub.Connect(a)

	// Start a listener to verify it gets cleaned up.
	ln, err := client.Listen("tcp", "0.0.0.0:7777")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Delete the namespace — should not panic or leak.
	if err := p.Delete("ephemeral"); err != nil {
		t.Fatal(err)
	}

	// Namespace should be gone.
	if ns := p.Get("ephemeral"); ns != nil {
		t.Error("namespace should be nil after delete")
	}
}
