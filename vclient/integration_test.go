package vclient_test

import (
	"net"
	"testing"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/slirp"
	"github.com/KarpelesLab/pktkit/vclient"
)

// TestLookupHostIP tests that LookupHost returns an IP address directly without DNS.
func TestLookupHostIP(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	client := vclient.New()
	defer client.Close()
	pktkit.ConnectL3(client, stack)
	client.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	addrs, err := client.LookupHost(t.Context(), "1.2.3.4")
	if err != nil {
		t.Fatalf("LookupHost for IP: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Errorf("LookupHost = %v, want [1.2.3.4]", addrs)
	}
}

// TestLookupHostNoDNS tests that LookupHost returns an error when no DNS servers are configured.
func TestLookupHostNoDNS(t *testing.T) {
	stack := slirp.New()
	defer stack.Close()

	client := vclient.New()
	defer client.Close()
	pktkit.ConnectL3(client, stack)
	client.SetIP(net.IPv4(10, 0, 0, 2), net.IPv4Mask(255, 255, 255, 0), net.IPv4(10, 0, 0, 1))

	_, err := client.LookupHost(t.Context(), "example.com")
	if err == nil {
		t.Error("expected error with no DNS servers")
	}
}
