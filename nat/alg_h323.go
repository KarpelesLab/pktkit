package nat

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const (
	h323Port       = 1720 // Q.931/H.225 signaling
	h323RTPTimeout = 120 * time.Second
	h245PortMin    = 1024 // H.245 dynamic port range lower bound
)

// H323Helper is a simplified ALG for the H.323 VoIP protocol suite.
//
// H.323 uses ASN.1 PER (Packed Encoding Rules) for its signaling messages,
// which makes full parsing extremely complex. This implementation uses a
// heuristic approach: it searches for 4-byte IPv4 address patterns and 6-byte
// transport address patterns (4-byte IP + 2-byte port) in the TCP payload,
// replacing inside addresses with outside addresses. While imperfect, this
// covers the majority of real-world H.323 NAT traversal cases where the
// addresses appear as contiguous binary values.
type H323Helper struct{}

// NewH323Helper returns a new H.323 ALG helper.
func NewH323Helper() *H323Helper {
	return &H323Helper{}
}

func (h *H323Helper) Name() string  { return "h323" }
func (h *H323Helper) Close() error  { return nil }

// MatchOutbound returns true for TCP traffic to port 1720 (Q.931/H.225).
func (h *H323Helper) MatchOutbound(proto uint8, dstPort uint16) bool {
	return proto == protoTCP && dstPort == h323Port
}

// ProcessOutbound searches the TCP payload for binary representations of the
// inside IP address and replaces them with the outside IP. When a 6-byte
// transport address (IP + port) is found, it creates NAT expectations for the
// associated H.245 or RTP channels.
func (h *H323Helper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
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
	if len(payload) < 4 {
		return pkt
	}

	insideIPBytes := m.InsideIP.As4()
	outsideIP := n.OutsideAddr()
	outsideIPBytes := outsideIP.As4()

	// Work on a copy of the payload
	newPayload := make([]byte, len(payload))
	copy(newPayload, payload)
	modified := false

	// Scan for transport addresses (6 bytes: IP + port) first, since they
	// are more specific than bare IP matches.
	for i := 0; i <= len(newPayload)-6; i++ {
		if newPayload[i] == insideIPBytes[0] &&
			newPayload[i+1] == insideIPBytes[1] &&
			newPayload[i+2] == insideIPBytes[2] &&
			newPayload[i+3] == insideIPBytes[3] {

			// Found inside IP — check if it's a transport address (IP + port)
			port := binary.BigEndian.Uint16(newPayload[i+4 : i+6])

			if port >= h245PortMin && port != 0 {
				// This looks like a transport address. Create an expectation
				// for the signaled port (could be H.245 or RTP).
				outsidePort := n.CreateMapping(protoTCP, m.InsideIP, port)
				if outsidePort == 0 {
					// Try UDP as well (RTP uses UDP)
					outsidePort = n.CreateMapping(protoUDP, m.InsideIP, port)
				}

				// Create TCP expectation for H.245 signaling
				n.AddExpectation(Expectation{
					Proto:      protoTCP,
					RemoteIP:   netip.Addr{}, // any remote
					RemotePort: 0,
					InsideIP:   m.InsideIP,
					InsidePort: port,
					Expires:    time.Now().Add(h323RTPTimeout),
				})

				// Create UDP expectation for RTP media
				n.AddExpectation(Expectation{
					Proto:      protoUDP,
					RemoteIP:   netip.Addr{}, // any remote
					RemotePort: 0,
					InsideIP:   m.InsideIP,
					InsidePort: port,
					Expires:    time.Now().Add(h323RTPTimeout),
				})

				// Also expect RTCP on port+1 if the port is even (RTP convention)
				if port%2 == 0 {
					n.AddExpectation(Expectation{
						Proto:      protoUDP,
						RemoteIP:   netip.Addr{},
						RemotePort: 0,
						InsideIP:   m.InsideIP,
						InsidePort: port + 1,
						Expires:    time.Now().Add(h323RTPTimeout),
					})
				}

				// Replace IP with outside IP
				copy(newPayload[i:i+4], outsideIPBytes[:])
				// Replace port with mapped outside port
				if outsidePort != 0 {
					binary.BigEndian.PutUint16(newPayload[i+4:i+6], outsidePort)
				}
				modified = true
				i += 5 // skip past the transport address
				continue
			}

			// Bare IP address match (not followed by a meaningful port).
			// Replace the IP only.
			copy(newPayload[i:i+4], outsideIPBytes[:])
			modified = true
			i += 3 // skip past the IP
		}
	}

	if !modified {
		return pkt
	}

	return h323RebuildPacket(pkt, ihl, newPayload)
}

// ProcessInbound searches the TCP payload for binary representations of the
// outside IP address and replaces them with the inside IP.
func (h *H323Helper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
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
	if len(payload) < 4 {
		return pkt
	}

	outsideIPBytes := n.OutsideAddr().As4()
	insideIPBytes := m.InsideIP.As4()

	newPayload := make([]byte, len(payload))
	copy(newPayload, payload)
	modified := false

	for i := 0; i <= len(newPayload)-6; i++ {
		if newPayload[i] == outsideIPBytes[0] &&
			newPayload[i+1] == outsideIPBytes[1] &&
			newPayload[i+2] == outsideIPBytes[2] &&
			newPayload[i+3] == outsideIPBytes[3] {

			// Check for transport address
			port := binary.BigEndian.Uint16(newPayload[i+4 : i+6])

			if port >= h245PortMin && port != 0 {
				// Rewrite IP back to inside
				copy(newPayload[i:i+4], insideIPBytes[:])
				// Rewrite port back to inside port if this is the mapped
				// outside port — otherwise leave it. For simplicity, rewrite
				// the signaling port back to the inside mapping port.
				if port == m.OutsidePort {
					binary.BigEndian.PutUint16(newPayload[i+4:i+6], m.InsidePort)
				}
				modified = true
				i += 5
				continue
			}

			// Bare IP match
			copy(newPayload[i:i+4], insideIPBytes[:])
			modified = true
			i += 3
		}
	}

	if !modified {
		return pkt
	}

	return h323RebuildPacket(pkt, ihl, newPayload)
}

// h323RebuildPacket reconstructs the IP+TCP packet with a modified payload,
// recalculating IP and TCP checksums. The payload size is the same (H.323
// binary address replacement is always same-length), so only checksums change.
func h323RebuildPacket(origPkt pktkit.Packet, ihl int, newPayload []byte) pktkit.Packet {
	tcpHdrLen := int(origPkt[ihl+12]>>4) * 4
	payloadOff := ihl + tcpHdrLen

	out := make(pktkit.Packet, len(origPkt))
	copy(out, origPkt)
	copy(out[payloadOff:], newPayload)

	// IP total length does not change (same payload size)

	// Recalculate IP checksum
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], pktkit.Checksum(out[:ihl]))

	// Recalculate TCP checksum from scratch
	h323RecalcTCPChecksum(out, ihl)

	return out
}

// h323RecalcTCPChecksum recalculates the TCP checksum.
func h323RecalcTCPChecksum(pkt pktkit.Packet, ihl int) {
	if len(pkt) < ihl+18 {
		return
	}
	tcp := pkt[ihl:]
	tcpLen := len(tcp)

	// Zero checksum
	binary.BigEndian.PutUint16(tcp[16:18], 0)

	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolTCP, srcIP, dstIP, uint16(tcpLen))
	dataCsum := pktkit.Checksum(tcp)
	combined := pktkit.CombineChecksums(^phCsum, ^dataCsum)
	binary.BigEndian.PutUint16(tcp[16:18], ^combined)
}
