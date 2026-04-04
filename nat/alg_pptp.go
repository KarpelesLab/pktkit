package nat

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const (
	pptpPort         = 1723
	pptpMagicCookie  = 0x1A2B3C4D
	pptpGRETimeout   = 120 * time.Second

	// PPTP control message types
	pptpStartControlConnReq = 1
	pptpOutgoingCallReq     = 7
	pptpOutgoingCallReply   = 8

	// GRE protocol number. The PPTP ALG tracks signaling only; actual GRE
	// forwarding requires NAT core support for protocol 47. The expectations
	// created here serve as markers for a future GRE-aware NAT implementation.
	protoGRE = 47
)

// PPTPHelper is an ALG for the Point-to-Point Tunneling Protocol (PPTP).
// It tracks PPTP control channel messages (TCP port 1723) to extract Call-IDs
// used in the associated GRE data tunnel, and creates NAT expectations for the
// GRE traffic.
//
// Note: GRE traffic uses IP protocol 47 (not TCP or UDP). Full PPTP NAT
// traversal requires the NAT core to handle GRE packets, including rewriting
// the Call-ID in the GRE key field (bytes 4-5 of the GRE header for PPTP
// enhanced GRE). This helper only handles the control signaling; GRE data
// forwarding is beyond its scope.
type PPTPHelper struct {
	mu    sync.Mutex
	calls map[uint16]pptpCallInfo // indexed by outside call ID
}

// pptpCallInfo tracks a PPTP call's identifiers for NAT mapping.
type pptpCallInfo struct {
	insideCallID  uint16
	outsideCallID uint16
	peerCallID    uint16
	insideIP      netip.Addr
	created       time.Time
}

// NewPPTPHelper returns a new PPTP ALG helper.
func NewPPTPHelper() *PPTPHelper {
	return &PPTPHelper{
		calls: make(map[uint16]pptpCallInfo),
	}
}

func (h *PPTPHelper) Name() string { return "pptp" }
func (h *PPTPHelper) Close() error { return nil }

// MatchOutbound returns true for TCP traffic to port 1723.
func (h *PPTPHelper) MatchOutbound(proto uint8, dstPort uint16) bool {
	return proto == protoTCP && dstPort == pptpPort
}

// ProcessOutbound parses PPTP control messages and tracks Call-IDs. For
// Outgoing-Call-Request messages, it extracts the Call-ID and creates GRE
// expectations.
func (h *PPTPHelper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+20 {
		return pkt
	}

	tcpHdrLen := int(pkt[ihl+12]>>4) * 4
	payloadOff := ihl + tcpHdrLen
	if payloadOff >= len(pkt) {
		return pkt
	}

	payload := pkt[payloadOff:]
	msgType, ctrlType, ok := pptpParseHeader(payload)
	if !ok || msgType != 1 {
		return pkt // not a control message or malformed
	}

	switch ctrlType {
	case pptpOutgoingCallReq:
		// Outgoing-Call-Request: Call-ID at bytes 12-13
		if len(payload) < 14 {
			return pkt
		}
		callID := binary.BigEndian.Uint16(payload[12:14])
		if callID == 0 {
			return pkt
		}

		// Track the call
		h.mu.Lock()
		h.calls[callID] = pptpCallInfo{
			insideCallID:  callID,
			outsideCallID: callID, // keep same call ID unless collision
			insideIP:      m.InsideIP,
			created:       time.Now(),
		}
		h.mu.Unlock()

		// Create expectation for GRE traffic associated with this call.
		// GRE uses IP protocol 47 — the expectation uses RemotePort=0
		// since GRE does not have ports, but the Call-ID in the GRE key
		// field identifies the tunnel.
		n.AddExpectation(Expectation{
			Proto:      protoGRE,
			RemoteIP:   netip.Addr{}, // any remote
			RemotePort: 0,
			InsideIP:   m.InsideIP,
			InsidePort: callID, // use call ID as port for GRE mapping
			Expires:    time.Now().Add(pptpGRETimeout),
		})

	case pptpOutgoingCallReply:
		// Outgoing-Call-Reply: Call-ID at bytes 12-13, Peer-Call-ID at 14-15
		if len(payload) < 16 {
			return pkt
		}
		callID := binary.BigEndian.Uint16(payload[12:14])
		peerCallID := binary.BigEndian.Uint16(payload[14:16])

		h.mu.Lock()
		h.calls[callID] = pptpCallInfo{
			insideCallID:  callID,
			outsideCallID: callID,
			peerCallID:    peerCallID,
			insideIP:      m.InsideIP,
			created:       time.Now(),
		}
		h.mu.Unlock()

		// Create GRE expectation for the reply direction as well
		n.AddExpectation(Expectation{
			Proto:      protoGRE,
			RemoteIP:   netip.Addr{},
			RemotePort: 0,
			InsideIP:   m.InsideIP,
			InsidePort: callID,
			Expires:    time.Now().Add(pptpGRETimeout),
		})

	case pptpStartControlConnReq:
		// Start-Control-Connection-Request: no special handling needed
		// beyond tracking that a PPTP session is being established.
	}

	return pkt
}

// ProcessInbound parses PPTP control messages from the server side,
// tracking Call-IDs in reply messages for proper GRE forwarding.
func (h *PPTPHelper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	if len(pkt) < ihl+20 {
		return pkt
	}

	tcpHdrLen := int(pkt[ihl+12]>>4) * 4
	payloadOff := ihl + tcpHdrLen
	if payloadOff >= len(pkt) {
		return pkt
	}

	payload := pkt[payloadOff:]
	msgType, ctrlType, ok := pptpParseHeader(payload)
	if !ok || msgType != 1 {
		return pkt
	}

	switch ctrlType {
	case pptpOutgoingCallReply:
		// Server reply: Call-ID at 12-13 is server's call ID,
		// Peer-Call-ID at 14-15 is our (client's) call ID.
		if len(payload) < 16 {
			return pkt
		}
		serverCallID := binary.BigEndian.Uint16(payload[12:14])
		peerCallID := binary.BigEndian.Uint16(payload[14:16])

		h.mu.Lock()
		if info, ok := h.calls[peerCallID]; ok {
			info.peerCallID = serverCallID
			h.calls[peerCallID] = info
		}
		h.mu.Unlock()

		// Refresh GRE expectation with the server's call ID
		n.AddExpectation(Expectation{
			Proto:      protoGRE,
			RemoteIP:   netip.Addr{},
			RemotePort: 0,
			InsideIP:   m.InsideIP,
			InsidePort: peerCallID,
			Expires:    time.Now().Add(pptpGRETimeout),
		})

	case pptpOutgoingCallReq:
		// Inbound call request from server (unusual but possible in some
		// configurations). Track similarly.
		if len(payload) < 14 {
			return pkt
		}
		callID := binary.BigEndian.Uint16(payload[12:14])

		h.mu.Lock()
		h.calls[callID] = pptpCallInfo{
			insideCallID:  callID,
			outsideCallID: callID,
			insideIP:      m.InsideIP,
			created:       time.Now(),
		}
		h.mu.Unlock()
	}

	return pkt
}

// pptpParseHeader validates and parses a PPTP control message header.
// Returns the message type (1=control), control message type, and whether
// the header is valid.
//
// PPTP control message header format:
//
//	Bytes 0-1:  Length (big-endian)
//	Bytes 2-3:  PPTP message type (1 = control message)
//	Bytes 4-7:  Magic cookie (0x1A2B3C4D)
//	Bytes 8-9:  Control message type
func pptpParseHeader(payload []byte) (msgType, ctrlType uint16, ok bool) {
	if len(payload) < 10 {
		return 0, 0, false
	}

	length := binary.BigEndian.Uint16(payload[0:2])
	if int(length) > len(payload) || length < 10 {
		return 0, 0, false
	}

	msgType = binary.BigEndian.Uint16(payload[2:4])
	magic := binary.BigEndian.Uint32(payload[4:8])
	if magic != pptpMagicCookie {
		return 0, 0, false
	}

	ctrlType = binary.BigEndian.Uint16(payload[8:10])
	return msgType, ctrlType, true
}
