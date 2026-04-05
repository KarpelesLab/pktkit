package nat

import (
	"bytes"
	"net/netip"
	"strconv"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const ircExpectTimeout = 60 * time.Second

// IRCHelper is an Application Layer Gateway for IRC DCC (Direct Client-to-Client).
//
// DCC commands embed the sender's IP address (as a 32-bit decimal integer)
// and a TCP port in the PRIVMSG payload. This helper rewrites those values
// to the NAT's outside address and an allocated outside port, and creates
// expectations so the incoming DCC connection is forwarded correctly.
type IRCHelper struct {
	ports map[uint16]struct{}
}

// NewIRCHelper returns a new IRC DCC ALG helper. If no ports are specified,
// the default IRC port 6667 is used.
func NewIRCHelper(ports ...uint16) *IRCHelper {
	h := &IRCHelper{ports: make(map[uint16]struct{})}
	if len(ports) == 0 {
		h.ports[6667] = struct{}{}
	} else {
		for _, p := range ports {
			h.ports[p] = struct{}{}
		}
	}
	return h
}

func (h *IRCHelper) Name() string { return "irc" }
func (h *IRCHelper) Close() error { return nil }

// MatchOutbound returns true for TCP connections to any of the configured
// IRC ports.
func (h *IRCHelper) MatchOutbound(proto uint8, dstPort uint16) bool {
	if proto != protoTCP {
		return false
	}
	_, ok := h.ports[dstPort]
	return ok
}

// ProcessOutbound inspects outbound TCP payload for DCC SEND and DCC CHAT
// commands, rewrites the embedded IP and port to the NAT's outside address,
// and creates expectations for incoming DCC connections.
func (h *IRCHelper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+20 {
		return pkt
	}
	tcp := pkt[ihl:]
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || len(tcp) < dataOff {
		return pkt
	}
	payload := tcp[dataOff:]
	if len(payload) == 0 {
		return pkt
	}

	// DCC commands are wrapped in CTCP delimiters: \x01DCC ...\x01
	// There may be surrounding PRIVMSG text; scan for the CTCP block.
	dccStart := bytes.Index(payload, []byte("\x01DCC "))
	if dccStart < 0 {
		return pkt
	}
	dccEnd := bytes.IndexByte(payload[dccStart+1:], '\x01')
	if dccEnd < 0 {
		return pkt // incomplete CTCP, pass through
	}
	dccEnd += dccStart + 1 // absolute index of closing \x01

	dccBody := payload[dccStart+1 : dccEnd] // "DCC SEND ..." or "DCC CHAT ..."

	fields := bytes.Fields(dccBody)
	// DCC SEND filename ip port [size]  → 4 or 5 fields
	// DCC CHAT chat ip port             → 4 fields
	if len(fields) < 4 {
		return pkt
	}

	cmd := string(fields[1]) // SEND or CHAT
	if cmd != "SEND" && cmd != "CHAT" {
		return pkt
	}

	// fields[2] = filename/chat-type, fields[len-2] = ip, fields[len-1] = port
	// For SEND with size: DCC SEND file ip port size (5 fields after DCC)
	// For SEND without:   DCC SEND file ip port      (4 fields after DCC)
	// For CHAT:           DCC CHAT chat ip port       (4 fields after DCC)
	var ipIdx, portIdx int
	if cmd == "SEND" && len(fields) >= 5 {
		// Could be "DCC SEND file ip port size" or "DCC SEND file ip port"
		// Try to parse: if fields[4] looks like a port and fields[3] looks like an IP...
		// Standard: ip is at index 3, port at 4, optional size at 5
		ipIdx = 3
		portIdx = 4
	} else {
		// "DCC CHAT chat ip port" or "DCC SEND file ip port"
		ipIdx = len(fields) - 2
		portIdx = len(fields) - 1
	}

	ipVal, err := strconv.ParseUint(string(fields[ipIdx]), 10, 32)
	if err != nil {
		return pkt
	}
	portVal, err := strconv.ParseUint(string(fields[portIdx]), 10, 16)
	if err != nil {
		return pkt
	}

	insideIPu32 := uint32(ipVal)
	insideIP := netip.AddrFrom4([4]byte{
		byte(insideIPu32 >> 24),
		byte(insideIPu32 >> 16),
		byte(insideIPu32 >> 8),
		byte(insideIPu32),
	})
	insidePort := uint16(portVal)

	// Allocate an outside port for the DCC connection.
	outsidePort := n.CreateMapping(protoTCP, insideIP, insidePort)
	if outsidePort == 0 {
		return pkt
	}

	// Create expectation for the incoming DCC connection.
	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   netip.Addr{}, // any remote can connect
		RemotePort: 0,
		InsideIP:   insideIP,
		InsidePort: insidePort,
		Expires:    time.Now().Add(ircExpectTimeout),
	})

	// Build the replacement DCC body with outside IP and port.
	outsideIPBytes := n.OutsideAddr().As4()
	outsideIPu32 := uint32(outsideIPBytes[0])<<24 |
		uint32(outsideIPBytes[1])<<16 |
		uint32(outsideIPBytes[2])<<8 |
		uint32(outsideIPBytes[3])

	// Reconstruct the DCC command.
	var newDCC []byte
	newDCC = append(newDCC, '\x01')
	// "DCC CMD arg"
	for i := 0; i < len(fields); i++ {
		if i > 0 {
			newDCC = append(newDCC, ' ')
		}
		switch i {
		case ipIdx:
			newDCC = strconv.AppendUint(newDCC, uint64(outsideIPu32), 10)
		case portIdx:
			newDCC = strconv.AppendUint(newDCC, uint64(outsidePort), 10)
		default:
			newDCC = append(newDCC, fields[i]...)
		}
	}
	newDCC = append(newDCC, '\x01')

	// Replace the original DCC block in the payload.
	var newPayload []byte
	newPayload = append(newPayload, payload[:dccStart]...)
	newPayload = append(newPayload, newDCC...)
	newPayload = append(newPayload, payload[dccEnd+1:]...)

	return rebuildTCPPacket(pkt, ihl, dataOff, newPayload)
}

// ProcessInbound is a no-op for IRC DCC. Incoming DCC connections are
// handled by the expectations registered in ProcessOutbound.
func (h *IRCHelper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	return pkt
}
