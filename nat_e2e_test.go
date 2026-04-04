package pktkit_test

import (
	"fmt"
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
)

// TestNATEndToEnd builds two L2 networks connected by a NAT:
//
//	Network 1 (10.0.0.0/24) — "upstream" with internet access:
//	  L2Hub1
//	  ├── DHCP server (10.0.0.10-100/24, gw .1, dns 1.1.1.1)
//	  ├── slirp (10.0.0.1) → real internet via NAT to host
//	  ├── serverClient (10.0.0.2) → runs an HTTP server
//	  └── NAT outside (10.0.0.3/24)
//
//	Network 2 (172.16.0.0/24) — "downstream" behind the NAT:
//	  L2Hub2
//	  ├── DHCP server (172.16.0.10-100/24, gw .1, dns 1.1.1.1)
//	  ├── NAT inside (172.16.0.1/24)
//	  └── testClient (gets IP via DHCP) → downloads from both networks
//
// The test client:
// 1. Downloads README.md from GitHub (through NAT → slirp → real internet)
// 2. Downloads from the HTTP server on network 1 (through NAT)
func TestNATEndToEnd(t *testing.T) {
	// =============================================
	// Network 1: upstream with internet + HTTP server
	// =============================================
	hub1 := pktkit.NewL2Hub()

	dhcp1 := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("10.0.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("10.0.0.10"),
		RangeEnd:   netip.MustParseAddr("10.0.0.100"),
		Router:     netip.MustParseAddr("10.0.0.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	})
	hub1.Connect(dhcp1)

	// Slirp: NATs to real host network (for internet access)
	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("10.0.0.1/24"))
	hub1.Connect(pktkit.NewL2Adapter(stack, nil))

	// HTTP server client on network 1
	serverClient := vclient.New()
	defer serverClient.Close()
	serverClient.SetIP(net.IPv4(10, 0, 0, 2), net.CIDRMask(24, 32), net.IPv4(10, 0, 0, 1))
	serverClient.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})
	hub1.Connect(pktkit.NewL2Adapter(serverClient, nil))

	// Start HTTP server on the serverClient
	ln, err := serverClient.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from network 1! Your addr: %s", r.RemoteAddr)
	})
	go http.Serve(ln, mux)

	// =============================================
	// NAT connecting network 1 ↔ network 2
	// =============================================
	natDevice := nat.New(
		netip.MustParsePrefix("172.16.0.1/24"), // inside (network 2)
		netip.MustParsePrefix("10.0.0.3/24"),   // outside (network 1)
	)
	defer natDevice.Close()

	// Connect NAT outside to network 1 (needs gateway for off-subnet routing)
	natOutAdapter := pktkit.NewL2Adapter(natDevice.Outside(), nil)
	natOutAdapter.SetGateway(netip.MustParseAddr("10.0.0.1"))
	hub1.Connect(natOutAdapter)

	// =============================================
	// Network 2: downstream behind NAT
	// =============================================
	hub2 := pktkit.NewL2Hub()

	dhcp2 := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("172.16.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("172.16.0.10"),
		RangeEnd:   netip.MustParseAddr("172.16.0.100"),
		Router:     netip.MustParseAddr("172.16.0.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	})
	hub2.Connect(dhcp2)

	// Connect NAT inside to network 2
	hub2.Connect(pktkit.NewL2Adapter(natDevice.Inside(), nil))

	// Test client on network 2
	testClient := vclient.New()
	defer testClient.Close()
	testClient.SetIP(net.IPv4zero, net.CIDRMask(0, 32), net.IPv4(172, 16, 0, 1))
	testClient.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})

	clientAdapter := pktkit.NewL2Adapter(testClient, nil)
	hub2.Connect(clientAdapter)
	clientAdapter.StartDHCP()

	// Wait for DHCP
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addr := testClient.Addr()
		if addr.IsValid() && addr.Addr().IsPrivate() {
			t.Logf("test client got IP via DHCP: %s", addr)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	addr := testClient.Addr()
	if !addr.IsValid() || !addr.Addr().IsPrivate() {
		t.Fatalf("DHCP failed: client addr = %s", addr)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: testClient.DialContext},
		Timeout:   15 * time.Second,
	}

	// =============================================
	// Test 1: Download from HTTP server on network 1
	// =============================================
	t.Run("network1_http_server", func(t *testing.T) {
		resp, err := httpClient.Get("http://10.0.0.2:8080/hello")
		if err != nil {
			t.Fatalf("GET /hello failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("response: %s", body)

		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "Hello from network 1") {
			t.Fatalf("unexpected body: %s", body)
		}
	})

	// =============================================
	// Test 2: Download from GitHub (through NAT → slirp → internet)
	// =============================================
	t.Run("internet_github", func(t *testing.T) {
		resp, err := httpClient.Get("https://raw.githubusercontent.com/KarpelesLab/pktkit/refs/heads/master/README.md")
		if err != nil {
			t.Fatalf("GET README.md failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("downloaded %d bytes from GitHub", len(body))

		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "pktkit") {
			t.Fatalf("body doesn't contain 'pktkit'")
		}
		t.Logf("first 200 bytes: %s", string(body[:min(200, len(body))]))
	})
}
