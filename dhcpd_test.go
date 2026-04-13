package pktkit_test

import (
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
)

// TestDHCPServerIntegration builds a full virtual network:
//
//	L2Hub (switch)
//	├── DHCPServer (192.168.0.10-100/24, router .1, dns 1.1.1.1/8.8.8.8)
//	├── slirp.Stack via L2Adapter (192.168.0.1/24, NATs to real internet)
//	└── vclient.Client via L2Adapter (gets IP from DHCP)
//
// The client downloads a file from GitHub to prove end-to-end connectivity.
func TestDHCPServerIntegration(t *testing.T) {
	// --- L2 switch ---
	hub := pktkit.NewL2Hub()

	// --- DHCP server ---
	dhcpSrv := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("192.168.0.1"),
		SubnetMask: net.CIDRMask(24, 32),
		RangeStart: netip.MustParseAddr("192.168.0.10"),
		RangeEnd:   netip.MustParseAddr("192.168.0.100"),
		Router:     netip.MustParseAddr("192.168.0.1"),
		DNS: []netip.Addr{
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("8.8.8.8"),
		},
		LeaseTime: 10 * time.Minute,
	})
	hub.Connect(dhcpSrv)

	// --- slirp NAT stack (acts as the router/gateway) ---
	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("192.168.0.1/24"))

	slirpAdapter := pktkit.NewL2Adapter(stack, nil)
	hub.Connect(slirpAdapter)

	// --- virtual client ---
	client := vclient.New()
	defer client.Close()

	// Set gateway and DNS (these are not part of L3Device but needed by vclient)
	client.SetIP(net.IPv4zero, net.CIDRMask(0, 32), net.IPv4(192, 168, 0, 1))
	client.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1), net.IPv4(8, 8, 8, 8)})

	clientAdapter := pktkit.NewL2Adapter(client, nil)
	hub.Connect(clientAdapter)

	// --- Start DHCP on the client adapter ---
	clientAdapter.StartDHCP()

	// Wait for the client to get an IP via DHCP
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		addr := client.Addr()
		if addr.IsValid() && addr.Addr().IsPrivate() {
			t.Logf("client got IP via DHCP: %s", addr)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	addr := client.Addr()
	if !addr.IsValid() || !addr.Addr().IsPrivate() {
		t.Fatalf("DHCP failed: client addr = %s", addr)
	}

	// --- Download a file from GitHub ---
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: client.DialContext,
		},
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get("https://raw.githubusercontent.com/KarpelesLab/pktkit/refs/heads/master/README.md")
	if err != nil {
		t.Fatalf("HTTP GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}

	if len(body) == 0 {
		t.Fatal("empty response body")
	}

	t.Logf("downloaded %d bytes", len(body))

	// Verify it looks like our README
	if got := string(body); len(got) < 10 {
		t.Fatalf("body too short: %q", got)
	}
	t.Logf("first 200 bytes: %s", string(body[:min(200, len(body))]))
}

// TestDHCPServerStaticLeases verifies that MACs with a static reservation
// always get their reserved IP, and that the reserved IP is never handed to
// a different MAC — even if the pool would otherwise cover it.
func TestDHCPServerStaticLeases(t *testing.T) {
	reservedMAC := net.HardwareAddr{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}
	otherMAC := net.HardwareAddr{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x02}
	reservedIP := netip.MustParseAddr("192.168.77.20")

	hub := pktkit.NewL2Hub()

	dhcpSrv := pktkit.NewDHCPServer(pktkit.DHCPServerConfig{
		ServerIP:   netip.MustParseAddr("192.168.77.1"),
		SubnetMask: net.CIDRMask(24, 32),
		// Pool overlaps with the reserved IP on purpose: the server
		// must still keep 192.168.77.20 off the dynamic allocation path.
		RangeStart: netip.MustParseAddr("192.168.77.10"),
		RangeEnd:   netip.MustParseAddr("192.168.77.30"),
		Router:     netip.MustParseAddr("192.168.77.1"),
		LeaseTime:  5 * time.Minute,
		StaticLeases: map[[6]byte]netip.Addr{
			{0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x01}: reservedIP,
		},
	})
	hub.Connect(dhcpSrv)

	run := func(mac net.HardwareAddr) netip.Prefix {
		client := vclient.New()
		defer client.Close()
		adapter := pktkit.NewL2Adapter(client, mac)
		defer adapter.Close()
		hub.Connect(adapter)
		adapter.StartDHCP()

		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			addr := client.Addr()
			if addr.IsValid() && addr.Addr().IsPrivate() {
				return addr
			}
			time.Sleep(10 * time.Millisecond)
		}
		return netip.Prefix{}
	}

	reservedAddr := run(reservedMAC)
	if !reservedAddr.IsValid() {
		t.Fatal("reserved MAC never got an IP")
	}
	if reservedAddr.Addr() != reservedIP {
		t.Errorf("reserved MAC got %s, want %s", reservedAddr.Addr(), reservedIP)
	}

	otherAddr := run(otherMAC)
	if !otherAddr.IsValid() {
		t.Fatal("other MAC never got an IP")
	}
	if otherAddr.Addr() == reservedIP {
		t.Errorf("other MAC was handed the reserved IP %s", reservedIP)
	}
	if !otherAddr.Addr().IsPrivate() {
		t.Errorf("other MAC got non-private IP %s", otherAddr.Addr())
	}
}
