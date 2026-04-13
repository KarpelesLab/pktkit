package qemu_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/qemu"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
)

// TestAdapterPerGuestIsolation verifies that two guests connecting through a
// qemu.Adapter with an L3Connector end up in isolated namespaces. Each guest
// is leased from an independent per-guest DHCP server, so both receive the
// same first address in the pool. Each can still reach an HTTP server on the
// host through the shared slirp stack via its own namespace.
func TestAdapterPerGuestIsolation(t *testing.T) {
	// HTTP server on the host that guests will reach via slirp NAT.
	hostLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostLn.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello from %s", r.RemoteAddr)
	})
	go http.Serve(hostLn, mux)
	hostURL := "http://" + hostLn.Addr().String() + "/whoami"

	ln, err := qemu.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	stack := slirp.New()
	defer stack.Close()
	stack.SetAddr(netip.MustParsePrefix("10.99.0.1/24"))

	adapter, err := qemu.NewAdapter(qemu.AdapterConfig{
		Listener:  ln,
		Connector: stack,
		Gateway:   netip.MustParsePrefix("10.99.0.1/24"),
		DHCP: &pktkit.DHCPServerConfig{
			ServerIP:   netip.MustParseAddr("10.99.0.1"),
			SubnetMask: net.CIDRMask(24, 32),
			RangeStart: netip.MustParseAddr("10.99.0.10"),
			RangeEnd:   netip.MustParseAddr("10.99.0.50"),
			Router:     netip.MustParseAddr("10.99.0.1"),
			DNS:        []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			LeaseTime:  5 * time.Minute,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.Close()
	go adapter.Serve()

	dialAddr := ln.Addr().String()

	type guest struct {
		client *vclient.Client
		close  func()
	}
	bring := func(t *testing.T) *guest {
		t.Helper()
		conn, err := qemu.Dial("tcp4", dialAddr)
		if err != nil {
			t.Fatal(err)
		}
		client := vclient.New()
		client.SetDNS([]net.IP{net.IPv4(1, 1, 1, 1)})
		adap := pktkit.NewL2Adapter(client, nil)
		pktkit.ConnectL2(adap, conn)
		adap.StartDHCP()

		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			a := client.Addr()
			if a.IsValid() && a.Addr().IsPrivate() {
				return &guest{
					client: client,
					close: func() {
						adap.Close()
						client.Close()
						conn.Close()
					},
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
		conn.Close()
		client.Close()
		adap.Close()
		t.Fatal("DHCP timed out")
		return nil
	}

	gA := bring(t)
	defer gA.close()
	gB := bring(t)
	defer gB.close()

	ipA := gA.client.Addr().Addr()
	ipB := gB.client.Addr().Addr()
	t.Logf("guest A: %s  guest B: %s", ipA, ipB)

	if ipA != ipB {
		t.Errorf("expected identical DHCP IPs (isolated namespaces), got A=%s B=%s", ipA, ipB)
	}
	expected := netip.MustParseAddr("10.99.0.10")
	if ipA != expected {
		t.Errorf("guest A got %s, expected %s", ipA, expected)
	}

	fetch := func(t *testing.T, label string, c *vclient.Client) {
		t.Helper()
		hc := &http.Client{
			Transport: &http.Transport{DialContext: c.DialContext},
			Timeout:   5 * time.Second,
		}
		resp, err := hc.Get(hostURL)
		if err != nil {
			t.Errorf("%s: GET failed: %v", label, err)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		t.Logf("%s: %s", label, body)
		if resp.StatusCode != 200 {
			t.Errorf("%s: status %d", label, resp.StatusCode)
		}
	}

	fetch(t, "guestA", gA.client)
	fetch(t, "guestB", gB.client)
}
