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

const ftpExpectTimeout = 60 * time.Second

// FTPHelper is an Application Layer Gateway for FTP (RFC 959).
// It rewrites PORT/EPRT commands in outbound traffic and
// 227/229 responses in inbound traffic so that active and passive
// mode data connections work through the NAT.
type FTPHelper struct{}

// NewFTPHelper returns a new FTP ALG helper.
func NewFTPHelper() *FTPHelper { return &FTPHelper{} }

func (h *FTPHelper) Name() string  { return "ftp" }
func (h *FTPHelper) Close() error  { return nil }

// MatchOutbound returns true for TCP connections to port 21 (FTP control).
func (h *FTPHelper) MatchOutbound(proto uint8, dstPort uint16) bool {
	return proto == protoTCP && dstPort == 21
}

// ProcessOutbound inspects outbound TCP payload for PORT and EPRT commands,
// rewrites the embedded IP:port to the NAT's outside address, and creates
// expectations for the resulting inbound data connections.
func (h *FTPHelper) ProcessOutbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
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

	upper := bytes.ToUpper(payload)

	if bytes.HasPrefix(upper, []byte("PORT ")) {
		return h.rewritePORT(n, pkt, m, ihl, dataOff, payload)
	}
	if bytes.HasPrefix(upper, []byte("EPRT ")) {
		return h.rewriteEPRT(n, pkt, m, ihl, dataOff, payload)
	}
	return pkt
}

// ProcessInbound inspects inbound TCP payload for 227 and 229 responses,
// rewrites passive-mode addresses, and creates expectations.
func (h *FTPHelper) ProcessInbound(n *NAT, pkt pktkit.Packet, m *NATMapping) pktkit.Packet {
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

	if bytes.HasPrefix(payload, []byte("227 ")) {
		return h.rewrite227(n, pkt, m, ihl, dataOff, payload)
	}
	if bytes.HasPrefix(payload, []byte("229 ")) {
		return h.handle229(n, pkt, m, ihl, dataOff, payload)
	}
	return pkt
}

// rewritePORT handles: PORT h1,h2,h3,h4,p1,p2\r\n
func (h *FTPHelper) rewritePORT(n *NAT, pkt pktkit.Packet, m *NATMapping, ihl, dataOff int, payload []byte) pktkit.Packet {
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return pkt // incomplete command
	}

	// Parse "PORT h1,h2,h3,h4,p1,p2"
	args := payload[5:end] // after "PORT "
	parts := bytes.Split(args, []byte(","))
	if len(parts) != 6 {
		return pkt
	}

	var ipBytes [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(string(parts[i]))
		if err != nil || v < 0 || v > 255 {
			return pkt
		}
		ipBytes[i] = byte(v)
	}
	p1, err1 := strconv.Atoi(string(parts[4]))
	p2, err2 := strconv.Atoi(string(parts[5]))
	if err1 != nil || err2 != nil {
		return pkt
	}
	insidePort := uint16(p1*256 + p2)
	insideIP := netip.AddrFrom4(ipBytes)

	// Allocate an outside port for the data connection and create a mapping.
	outsideDataPort := n.CreateMapping(protoTCP, insideIP, insidePort)
	if outsideDataPort == 0 {
		return pkt
	}

	// Register expectation: server will connect to our outside data port.
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   dstIP,
		RemotePort: 0, // server picks source port
		InsideIP:   insideIP,
		InsidePort: insidePort,
		Expires:    time.Now().Add(ftpExpectTimeout),
	})

	// Build replacement command with outside IP:port.
	outsideIP := n.OutsideAddr().As4()
	newPayload := fmt.Appendf(nil, "PORT %d,%d,%d,%d,%d,%d\r\n",
		outsideIP[0], outsideIP[1], outsideIP[2], outsideIP[3],
		outsideDataPort/256, outsideDataPort%256)

	// Append any data after the original command's \r\n.
	tail := payload[end+2:]
	newPayload = append(newPayload, tail...)

	return rebuildTCPPacket(pkt, ihl, dataOff, newPayload)
}

// rewriteEPRT handles: EPRT |1|ip|port|\r\n
func (h *FTPHelper) rewriteEPRT(n *NAT, pkt pktkit.Packet, m *NATMapping, ihl, dataOff int, payload []byte) pktkit.Packet {
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return pkt
	}

	args := payload[5:end] // after "EPRT "
	// Expected format: |1|ip|port|
	if len(args) < 7 || args[0] != '|' {
		return pkt
	}
	fields := bytes.Split(args[1:], []byte("|"))
	if len(fields) < 3 {
		return pkt
	}
	if string(fields[0]) != "1" {
		return pkt // only IPv4
	}

	insideIP, err := netip.ParseAddr(string(fields[1]))
	if err != nil || !insideIP.Is4() {
		return pkt
	}
	insidePort64, err := strconv.ParseUint(string(fields[2]), 10, 16)
	if err != nil {
		return pkt
	}
	insidePort := uint16(insidePort64)

	outsideDataPort := n.CreateMapping(protoTCP, insideIP, insidePort)
	if outsideDataPort == 0 {
		return pkt
	}

	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   dstIP,
		RemotePort: 0,
		InsideIP:   insideIP,
		InsidePort: insidePort,
		Expires:    time.Now().Add(ftpExpectTimeout),
	})

	outsideIP := n.OutsideAddr()
	newPayload := fmt.Appendf(nil, "EPRT |1|%s|%d|\r\n", outsideIP.String(), outsideDataPort)
	tail := payload[end+2:]
	newPayload = append(newPayload, tail...)

	return rebuildTCPPacket(pkt, ihl, dataOff, newPayload)
}

// rewrite227 handles: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)\r\n
func (h *FTPHelper) rewrite227(n *NAT, pkt pktkit.Packet, m *NATMapping, ihl, dataOff int, payload []byte) pktkit.Packet {
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return pkt
	}

	// Find the parenthesized address.
	lp := bytes.IndexByte(payload[:end], '(')
	rp := bytes.IndexByte(payload[:end], ')')
	if lp < 0 || rp < 0 || rp <= lp {
		return pkt
	}

	inner := payload[lp+1 : rp]
	parts := bytes.Split(inner, []byte(","))
	if len(parts) != 6 {
		return pkt
	}

	var serverIPBytes [4]byte
	for i := 0; i < 4; i++ {
		v, err := strconv.Atoi(string(parts[i]))
		if err != nil || v < 0 || v > 255 {
			return pkt
		}
		serverIPBytes[i] = byte(v)
	}
	p1, err1 := strconv.Atoi(string(parts[4]))
	p2, err2 := strconv.Atoi(string(parts[5]))
	if err1 != nil || err2 != nil {
		return pkt
	}
	serverPort := uint16(p1*256 + p2)
	serverIP := netip.AddrFrom4(serverIPBytes)

	// Create expectation: inside client will connect to server's data port.
	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   serverIP,
		RemotePort: serverPort,
		InsideIP:   m.InsideIP,
		InsidePort: 0, // client picks source port; the NAT will allocate
		Expires:    time.Now().Add(ftpExpectTimeout),
	})

	// Rewrite the server address to the NAT's inside address so the client
	// connects through the NAT. We keep the server port as-is since the
	// client will make an outbound connection to it.
	insideIP := n.InsideAddr().As4()
	newInner := fmt.Appendf(nil, "%d,%d,%d,%d,%d,%d",
		serverIPBytes[0], serverIPBytes[1], serverIPBytes[2], serverIPBytes[3],
		serverPort/256, serverPort%256)
	// Only rewrite if the server reported a private/different IP; otherwise
	// just create the expectation and pass through. In standard NAT operation
	// the addresses stay the same for passive mode since the client makes an
	// outbound connection. We still need the expectation.
	_ = insideIP
	_ = newInner

	// For passive mode the client initiates the data connection outbound,
	// so the normal NAT translation handles it. We just need the expectation.
	return pkt
}

// handle229 handles: 229 Entering Extended Passive Mode (|||port|)\r\n
func (h *FTPHelper) handle229(n *NAT, pkt pktkit.Packet, m *NATMapping, ihl, dataOff int, payload []byte) pktkit.Packet {
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		return pkt
	}

	// Find (|||port|)
	lp := bytes.IndexByte(payload[:end], '(')
	rp := bytes.IndexByte(payload[:end], ')')
	if lp < 0 || rp < 0 || rp <= lp {
		return pkt
	}

	inner := payload[lp+1 : rp]
	if !bytes.HasPrefix(inner, []byte("|||")) || !bytes.HasSuffix(inner, []byte("|")) {
		return pkt
	}
	portStr := inner[3 : len(inner)-1]
	port64, err := strconv.ParseUint(string(portStr), 10, 16)
	if err != nil {
		return pkt
	}
	serverPort := uint16(port64)

	// The server IP is the same as the control connection's remote IP.
	serverIP := netip.AddrFrom4([4]byte(pkt[12:16]))

	n.AddExpectation(Expectation{
		Proto:      protoTCP,
		RemoteIP:   serverIP,
		RemotePort: serverPort,
		InsideIP:   m.InsideIP,
		InsidePort: 0,
		Expires:    time.Now().Add(ftpExpectTimeout),
	})

	return pkt
}

// rebuildTCPPacket replaces the TCP payload of a packet and recalculates
// IP total length, IP header checksum, and TCP checksum from scratch.
func rebuildTCPPacket(pkt pktkit.Packet, ihl, tcpDataOff int, newPayload []byte) pktkit.Packet {
	// Build new packet: IP header + TCP header + new payload.
	ipHdr := pkt[:ihl]
	tcpHdr := pkt[ihl : ihl+tcpDataOff]

	totalLen := ihl + tcpDataOff + len(newPayload)
	out := make(pktkit.Packet, totalLen)
	copy(out, ipHdr)
	copy(out[ihl:], tcpHdr)
	copy(out[ihl+tcpDataOff:], newPayload)

	// Update IP total length.
	binary.BigEndian.PutUint16(out[2:4], uint16(totalLen))

	// Recalculate IP header checksum from scratch.
	binary.BigEndian.PutUint16(out[10:12], 0)
	binary.BigEndian.PutUint16(out[10:12], pktkit.Checksum(out[:ihl]))

	// Recalculate TCP checksum from scratch using pseudo-header.
	tcpLen := uint16(totalLen - ihl)
	srcIP := netip.AddrFrom4([4]byte(out[12:16]))
	dstIP := netip.AddrFrom4([4]byte(out[16:20]))

	tcpSegment := out[ihl:]
	// Zero existing checksum.
	binary.BigEndian.PutUint16(tcpSegment[16:18], 0)

	phCsum := pktkit.PseudoHeaderChecksum(pktkit.ProtocolTCP, srcIP, dstIP, tcpLen)
	tcpCsum := pktkit.Checksum(tcpSegment)
	// Combine pseudo-header and TCP segment checksums.
	sum := uint32(^phCsum) + uint32(^tcpCsum)
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(tcpSegment[16:18], ^uint16(sum))

	return out
}
