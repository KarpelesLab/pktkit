package nat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/KarpelesLab/pktkit"
)

const (
	sipPort       = 5060
	sipRTPTimeout = 120 * time.Second
)

// SIPHelper is an ALG for the Session Initiation Protocol (SIP), used in VoIP.
// It rewrites embedded IP addresses and ports in SIP headers (Via, Contact) and
// SDP bodies (c= connection, m= media lines), and creates expectations for the
// resulting RTP/RTCP media streams.
type SIPHelper struct{}

// NewSIPHelper returns a new SIP ALG helper.
func NewSIPHelper() *SIPHelper {
	return &SIPHelper{}
}

func (h *SIPHelper) Name() string  { return "sip" }
func (h *SIPHelper) Close() error  { return nil }

// MatchOutbound returns true for UDP or TCP traffic to port 5060.
func (h *SIPHelper) MatchOutbound(proto uint8, dstPort uint16) bool {
	return dstPort == sipPort && (proto == protoUDP || proto == protoTCP)
}

// ProcessOutbound rewrites inside addresses to outside addresses in SIP
// headers and SDP bodies. It creates NAT expectations for RTP/RTCP streams
// found in SDP media lines.
func (h *SIPHelper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	proto := pkt[9]

	var hdrLen int
	if proto == protoTCP {
		if len(pkt) < ihl+20 {
			return pkt
		}
		hdrLen = int(pkt[ihl+12]>>4) * 4
	} else {
		hdrLen = 8 // UDP header
	}

	payloadOff := ihl + hdrLen
	if payloadOff >= len(pkt) {
		return pkt
	}

	payload := pkt[payloadOff:]
	if len(payload) == 0 {
		return pkt
	}

	insideIP := m.InsideIP
	outsideIP := n.OutsideAddr()

	insideAddr := insideIP.String()
	outsideAddr := outsideIP.String()
	insideHostPort := fmt.Sprintf("%s:%d", insideAddr, m.InsidePort)
	outsideHostPort := fmt.Sprintf("%s:%d", outsideAddr, m.OutsidePort)

	newPayload := make([]byte, len(payload))
	copy(newPayload, payload)

	// Rewrite Via: and Contact: headers with IP:port
	newPayload = sipRewriteHeader(newPayload, []byte("Via:"), []byte(insideHostPort), []byte(outsideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Via: "), []byte(insideHostPort), []byte(outsideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("v:"), []byte(insideHostPort), []byte(outsideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact:"), []byte(insideHostPort), []byte(outsideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact: "), []byte(insideHostPort), []byte(outsideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("m:"), []byte(insideHostPort), []byte(outsideHostPort))

	// Rewrite bare IP addresses only in relevant SIP headers (Via, Contact),
	// not globally across the entire message body.
	newPayload = sipRewriteHeader(newPayload, []byte("Via:"), []byte(insideAddr), []byte(outsideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Via: "), []byte(insideAddr), []byte(outsideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("v:"), []byte(insideAddr), []byte(outsideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact:"), []byte(insideAddr), []byte(outsideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact: "), []byte(insideAddr), []byte(outsideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("m:"), []byte(insideAddr), []byte(outsideAddr))

	// Process SDP body if present
	sdpStart := bytes.Index(newPayload, []byte("\r\n\r\n"))
	if sdpStart >= 0 {
		// Check for SDP content type
		headerPart := newPayload[:sdpStart]
		if bytes.Contains(bytes.ToLower(headerPart), []byte("content-type: application/sdp")) ||
			bytes.Contains(bytes.ToLower(headerPart), []byte("c: application/sdp")) {
			sdpBody := newPayload[sdpStart+4:]
			newSDP := h.rewriteSDPOutbound(n, sdpBody, m, outsideAddr)
			if !bytes.Equal(newSDP, sdpBody) {
				// Rebuild payload with new SDP and updated Content-Length
				newPayload = sipUpdateContentLength(newPayload[:sdpStart+4], newSDP)
			}
		}
	}

	if bytes.Equal(newPayload, payload) {
		return pkt
	}

	return sipRebuildPacket(pkt, ihl, proto, newPayload)
}

// ProcessInbound rewrites outside addresses back to inside addresses in SIP
// headers and SDP bodies.
func (h *SIPHelper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
	ihl := int(pkt[0]&0x0F) * 4
	proto := pkt[9]

	var hdrLen int
	if proto == protoTCP {
		if len(pkt) < ihl+20 {
			return pkt
		}
		hdrLen = int(pkt[ihl+12]>>4) * 4
	} else {
		hdrLen = 8
	}

	payloadOff := ihl + hdrLen
	if payloadOff >= len(pkt) {
		return pkt
	}

	payload := pkt[payloadOff:]
	if len(payload) == 0 {
		return pkt
	}

	insideIP := m.InsideIP
	outsideIP := n.OutsideAddr()

	insideAddr := insideIP.String()
	outsideAddr := outsideIP.String()
	insideHostPort := fmt.Sprintf("%s:%d", insideAddr, m.InsidePort)
	outsideHostPort := fmt.Sprintf("%s:%d", outsideAddr, m.OutsidePort)

	newPayload := make([]byte, len(payload))
	copy(newPayload, payload)

	// Reverse: rewrite outside → inside in headers
	newPayload = sipRewriteHeader(newPayload, []byte("Via:"), []byte(outsideHostPort), []byte(insideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Via: "), []byte(outsideHostPort), []byte(insideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("v:"), []byte(outsideHostPort), []byte(insideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact:"), []byte(outsideHostPort), []byte(insideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact: "), []byte(outsideHostPort), []byte(insideHostPort))
	newPayload = sipRewriteHeader(newPayload, []byte("m:"), []byte(outsideHostPort), []byte(insideHostPort))

	// Rewrite bare IP addresses only in relevant SIP headers.
	newPayload = sipRewriteHeader(newPayload, []byte("Via:"), []byte(outsideAddr), []byte(insideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Via: "), []byte(outsideAddr), []byte(insideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("v:"), []byte(outsideAddr), []byte(insideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact:"), []byte(outsideAddr), []byte(insideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("Contact: "), []byte(outsideAddr), []byte(insideAddr))
	newPayload = sipRewriteHeader(newPayload, []byte("m:"), []byte(outsideAddr), []byte(insideAddr))

	// Process SDP body
	sdpStart := bytes.Index(newPayload, []byte("\r\n\r\n"))
	if sdpStart >= 0 {
		headerPart := newPayload[:sdpStart]
		if bytes.Contains(bytes.ToLower(headerPart), []byte("content-type: application/sdp")) ||
			bytes.Contains(bytes.ToLower(headerPart), []byte("c: application/sdp")) {
			sdpBody := newPayload[sdpStart+4:]
			newSDP := sipRewriteSDPAddr(sdpBody, outsideAddr, insideAddr)
			if !bytes.Equal(newSDP, sdpBody) {
				newPayload = sipUpdateContentLength(newPayload[:sdpStart+4], newSDP)
			}
		}
	}

	if bytes.Equal(newPayload, payload) {
		return pkt
	}

	return sipRebuildPacket(pkt, ihl, proto, newPayload)
}

// rewriteSDPOutbound rewrites SDP connection and media lines, replacing
// inside addresses with outside addresses, and creates RTP/RTCP expectations.
func (h *SIPHelper) rewriteSDPOutbound(n *NAT, sdp []byte, m *NATMapping, outsideAddr string) []byte {
	insideAddr := m.InsideIP.String()
	lines := bytes.Split(sdp, []byte("\r\n"))
	var result [][]byte

	remoteIP := netip.Addr{} // populated if we can determine the remote
	for _, line := range lines {
		switch {
		case bytes.HasPrefix(line, []byte("c=IN IP4 ")):
			// Rewrite connection line
			rest := line[len("c=IN IP4 "):]
			// Extract the remote IP for expectations if this is not our inside IP
			if addr := string(bytes.TrimSpace(rest)); addr != insideAddr {
				remoteIP, _ = netip.ParseAddr(addr)
			}
			line = []byte("c=IN IP4 " + outsideAddr)

		case bytes.HasPrefix(line, []byte("m=")):
			// Parse media line: m=audio PORT RTP/AVP ...
			newLine, insidePort := sipParseMediaLine(line, n, m, outsideAddr, remoteIP)
			if insidePort != 0 {
				line = newLine
			}
		}
		result = append(result, line)
	}

	return bytes.Join(result, []byte("\r\n"))
}

// sipRewriteSDPAddr replaces IP addresses in SDP c= lines.
func sipRewriteSDPAddr(sdp []byte, oldAddr, newAddr string) []byte {
	old := []byte("c=IN IP4 " + oldAddr)
	new := []byte("c=IN IP4 " + newAddr)
	return bytes.ReplaceAll(sdp, old, new)
}

// sipParseMediaLine parses an SDP m= line, creates RTP/RTCP expectations,
// and returns the rewritten line with the outside port.
func sipParseMediaLine(line []byte, n *NAT, m *NATMapping, outsideAddr string, remoteIP netip.Addr) ([]byte, uint16) {
	// m=audio 8000 RTP/AVP 0 8
	parts := bytes.Fields(line)
	if len(parts) < 3 {
		return line, 0
	}

	port, err := strconv.ParseUint(string(parts[1]), 10, 16)
	if err != nil || port == 0 {
		return line, 0
	}
	insidePort := uint16(port)

	// Allocate an even outside port for RTP (RFC 3550 convention).
	var rtpOutPort uint16
	for attempts := 0; attempts < 100; attempts++ {
		p := n.AllocOutsidePort(protoUDP)
		if p == 0 {
			return line, 0 // port pool exhausted
		}
		if p%2 == 0 {
			rtpOutPort = p
			break
		}
		// Odd port — release it back by not using it. The NAT port allocator
		// is a simple counter, so we just keep trying until we find an even one.
	}
	if rtpOutPort == 0 {
		return line, 0
	}

	// Create mapping and expectation for RTP
	n.CreateMapping(protoUDP, m.InsideIP, insidePort)
	n.AddExpectation(Expectation{
		Proto:      protoUDP,
		RemoteIP:   remoteIP,
		RemotePort: 0, // any port — remote RTP port not yet known
		InsideIP:   m.InsideIP,
		InsidePort: insidePort,
		Expires:    time.Now().Add(sipRTPTimeout),
	})

	// Create expectation for RTCP (RTP port + 1)
	rtcpInsidePort := insidePort + 1
	n.CreateMapping(protoUDP, m.InsideIP, rtcpInsidePort)
	n.AddExpectation(Expectation{
		Proto:      protoUDP,
		RemoteIP:   remoteIP,
		RemotePort: 0,
		InsideIP:   m.InsideIP,
		InsidePort: rtcpInsidePort,
		Expires:    time.Now().Add(sipRTPTimeout),
	})

	// Rewrite media port in the line
	parts[1] = []byte(strconv.FormatUint(uint64(rtpOutPort), 10))
	return bytes.Join(parts, []byte(" ")), insidePort
}

// sipRewriteHeader replaces oldVal with newVal only within header lines that
// start with the given prefix (case-insensitive match on the prefix).
func sipRewriteHeader(payload, prefix, oldVal, newVal []byte) []byte {
	if bytes.Equal(oldVal, newVal) {
		return payload
	}
	lowerPrefix := bytes.ToLower(prefix)
	lines := bytes.Split(payload, []byte("\r\n"))
	changed := false
	for i, line := range lines {
		if len(line) < len(prefix) {
			continue
		}
		if !bytes.EqualFold(line[:len(prefix)], lowerPrefix) {
			continue
		}
		newLine := bytes.ReplaceAll(line, oldVal, newVal)
		if !bytes.Equal(newLine, line) {
			lines[i] = newLine
			changed = true
		}
	}
	if !changed {
		return payload
	}
	return bytes.Join(lines, []byte("\r\n"))
}

// sipUpdateContentLength rebuilds the SIP message with the correct
// Content-Length header for the given SDP body.
func sipUpdateContentLength(headers []byte, sdpBody []byte) []byte {
	newCL := []byte(fmt.Sprintf("%d", len(sdpBody)))

	// Find and rewrite Content-Length header.
	lowerHeaders := bytes.ToLower(headers)
	clIdx := bytes.Index(lowerHeaders, []byte("content-length:"))
	if clIdx < 0 {
		// Try SIP compact form "l:" — must appear at start of a line.
		for off := 0; off < len(lowerHeaders); {
			idx := bytes.Index(lowerHeaders[off:], []byte("l:"))
			if idx < 0 {
				break
			}
			absIdx := off + idx
			if absIdx == 0 || (absIdx >= 2 && lowerHeaders[absIdx-2] == '\r' && lowerHeaders[absIdx-1] == '\n') {
				clIdx = absIdx
				break
			}
			off = absIdx + 2
		}
	}

	if clIdx >= 0 {
		// Find the end of this header line
		lineEnd := bytes.Index(headers[clIdx:], []byte("\r\n"))
		if lineEnd >= 0 {
			// Find the colon
			colonIdx := bytes.IndexByte(headers[clIdx:clIdx+lineEnd], ':')
			if colonIdx >= 0 {
				before := headers[:clIdx+colonIdx+1]
				after := headers[clIdx+lineEnd:]
				headers = append(append(append([]byte{}, before...), ' '), append(newCL, after...)...)
			}
		}
	}

	result := make([]byte, 0, len(headers)+len(sdpBody))
	result = append(result, headers...)
	result = append(result, sdpBody...)
	return result
}

// sipRebuildPacket reconstructs the IP packet with a modified payload,
// updating lengths and checksums.
func sipRebuildPacket(origPkt pktkit.Packet, ihl int, proto uint8, newPayload []byte) pktkit.Packet {
	var l4HdrLen int
	if proto == protoTCP {
		if len(origPkt) < ihl+20 {
			return origPkt
		}
		l4HdrLen = int(origPkt[ihl+12]>>4) * 4
	} else {
		l4HdrLen = 8
	}

	// Build new packet: IP header + L4 header + new payload
	newTotalLen := ihl + l4HdrLen + len(newPayload)
	out := make(pktkit.Packet, newTotalLen)
	copy(out[:ihl], origPkt[:ihl])

	// Copy L4 header
	if len(origPkt) >= ihl+l4HdrLen {
		copy(out[ihl:ihl+l4HdrLen], origPkt[ihl:ihl+l4HdrLen])
	}

	// Copy new payload
	copy(out[ihl+l4HdrLen:], newPayload)

	// Update IP total length
	binary.BigEndian.PutUint16(out[2:4], uint16(newTotalLen))

	// Recalculate IP checksum from scratch
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], pktkit.Checksum(out[:ihl]))

	// Recalculate L4 checksum
	if proto == protoTCP {
		sipRecalcTCPChecksum(out, ihl)
	} else if proto == protoUDP {
		sipRecalcUDPChecksum(out, ihl)
	}

	return out
}

// sipRecalcTCPChecksum recalculates the TCP checksum from scratch.
func sipRecalcTCPChecksum(pkt pktkit.Packet, ihl int) {
	if len(pkt) < ihl+18 {
		return
	}
	tcp := pkt[ihl:]
	tcpLen := len(tcp)

	// Zero the checksum field
	binary.BigEndian.PutUint16(tcp[16:18], 0)

	// Pseudo-header
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolTCP, srcIP, dstIP, uint16(tcpLen))
	dataCsum := pktkit.Checksum(tcp)
	combined := pktkit.CombineChecksums(^phCsum, ^dataCsum)
	binary.BigEndian.PutUint16(tcp[16:18], ^combined)
}

// sipRecalcUDPChecksum recalculates the UDP checksum from scratch.
func sipRecalcUDPChecksum(pkt pktkit.Packet, ihl int) {
	if len(pkt) < ihl+8 {
		return
	}
	udp := pkt[ihl:]
	udpLen := len(udp)

	// Update UDP length field
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))

	// Zero the checksum field
	binary.BigEndian.PutUint16(udp[6:8], 0)

	// Pseudo-header
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolUDP, srcIP, dstIP, uint16(udpLen))
	dataCsum := pktkit.Checksum(udp)
	combined := pktkit.CombineChecksums(^phCsum, ^dataCsum)
	final := ^combined
	if final == 0 {
		final = 0xFFFF // UDP checksum of 0 is transmitted as 0xFFFF
	}
	binary.BigEndian.PutUint16(udp[6:8], final)
}
