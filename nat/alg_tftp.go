package nat

import (
	"net/netip"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const tftpExpectTimeout = 60 * time.Second

// TFTPHelper is an Application Layer Gateway for TFTP (RFC 1350).
//
// TFTP uses a well-known port (69) only for the initial request. The server
// replies from a random ephemeral port, so the NAT needs an expectation to
// allow the response through. This helper creates that expectation when it
// sees an outbound RRQ or WRQ.
type TFTPHelper struct{}

// NewTFTPHelper returns a new TFTP ALG helper.
func NewTFTPHelper() *TFTPHelper { return &TFTPHelper{} }

func (h *TFTPHelper) Name() string  { return "tftp" }
func (h *TFTPHelper) Close() error  { return nil }

// MatchOutbound returns true for UDP connections to port 69 (TFTP).
func (h *TFTPHelper) MatchOutbound(proto uint8, dstPort uint16) bool {
	return proto == protoUDP && dstPort == 69
}

// ProcessOutbound creates an expectation for the TFTP server's reply.
// The server will respond from its IP on a random ephemeral port to the
// client's mapped outside port.
func (h *TFTPHelper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+8 {
		return pkt
	}

	// Extract server (destination) IP from the IP header.
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))

	// The server will reply from dstIP on an arbitrary port to our outside port.
	n.AddExpectation(Expectation{
		Proto:      protoUDP,
		RemoteIP:   dstIP,
		RemotePort: 0, // server picks a random source port
		InsideIP:   m.InsideIP,
		InsidePort: m.InsidePort,
		Expires:    time.Now().Add(tftpExpectTimeout),
	})

	return pkt
}

// ProcessInbound is a no-op for TFTP. The server's response is handled by
// the expectation registered in ProcessOutbound.
func (h *TFTPHelper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	return pkt
}
