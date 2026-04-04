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

// TestNAT64EndToEnd builds an IPv6-only client network connected to an IPv4
// network via NAT64:
//
//	IPv6 network (L3Hub):                 IPv4 network (L2Hub, 10.0.0.0/24):
//	  NAT64 inside (2001:db8::1/64)         NAT64 outside (10.0.0.2/24, gw .1)
//	  vclient (2001:db8::2)                 slirp (10.0.0.1) → real internet
//	                                        HTTP server (10.0.0.3)
//	                                        DHCP server
//
// The IPv6 client accesses IPv4 hosts by sending to ::ffff:x.x.x.x addresses.
// The NAT64 translates IPv6↔IPv4. DNS goes via ::ffff:1.1.1.1.
//
// Test 1: Client fetches from HTTP server at ::ffff:10.0.0.3:8080
// Test 2: Client downloads README.md from GitHub via ::ffff:1.1.1.1 DNS
func TestNAT64EndToEnd(t *testing.T) {
	// =============================================
	// IPv4 network with internet and HTTP server
	// =============================================
	hub4 := pktkit.NewL2Hub()

	dhcp4 := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("10.0.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("10.0.0.10"),
		RangeEnd:   netip.MustParseAddr("10.0.0.100"),
		Router:     netip.MustParseAddr("10.0.0.1"),
		DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	})
	hub4.Connect(dhcp4)

	// Slirp for real internet access
	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("10.0.0.1/24"))
	hub4.Connect(pktkit.NewL2Adapter(stack, nil))

	// HTTP server on the IPv4 network
	serverClient := vclient.New()
	defer serverClient.Close()
	serverClient.SetIP(net.IPv4(10, 0, 0, 3), net.CIDRMask(24, 32), net.IPv4(10, 0, 0, 1))
	hub4.Connect(pktkit.NewL2Adapter(serverClient, nil))

	ln, err := serverClient.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from IPv4 network! Remote: %s", r.RemoteAddr)
	})
	go http.Serve(ln, mux)

	// =============================================
	// NAT64: bridges IPv6 inside ↔ IPv4 outside
	// =============================================
	nat64 := nat.NewNAT64(
		netip.MustParsePrefix("2001:db8::1/64"),
		netip.MustParsePrefix("10.0.0.2/24"),
	)
	defer nat64.Close()

	// Connect NAT64 outside to IPv4 network
	natOutAdapter := pktkit.NewL2Adapter(nat64.Outside(), nil)
	natOutAdapter.SetGateway(netip.MustParseAddr("10.0.0.1"))
	hub4.Connect(natOutAdapter)

	// =============================================
	// IPv6-only client network (L3Hub)
	// =============================================
	hub6 := pktkit.NewL3Hub()
	hub6.Connect(nat64.Inside())
	hub6.SetDefaultRoute(nat64.Inside())

	// IPv6-only client
	client := vclient.New()
	defer client.Close()
	client.SetIPv6(net.ParseIP("2001:db8::2"))
	client.SetAddr(netip.MustParsePrefix("2001:db8::2/64"))
	// DNS via NAT64: ::ffff:1.1.1.1
	client.SetDNS6([]net.IP{net.ParseIP("::ffff:1.1.1.1")})

	hub6.Connect(client)

	httpClient := &http.Client{
		Transport: &http.Transport{DialContext: client.DialContext},
		Timeout:   15 * time.Second,
	}

	// =============================================
	// Test 1: Fetch from HTTP server via NAT64
	// =============================================
	t.Run("ipv4_http_via_nat64", func(t *testing.T) {
		// ::ffff:10.0.0.3 = IPv4-mapped address for 10.0.0.3
		resp, err := httpClient.Get("http://[::ffff:10.0.0.3]:8080/hello")
		if err != nil {
			t.Fatalf("GET /hello failed: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		t.Logf("response: %s", body)

		if resp.StatusCode != 200 {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "Hello from IPv4 network") {
			t.Fatalf("unexpected body: %s", body)
		}
	})

	// =============================================
	// Test 2: Download from GitHub via NAT64 + slirp
	// =============================================
	t.Run("internet_via_nat64", func(t *testing.T) {
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
