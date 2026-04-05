package nat

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/KarpelesLab/pktkit"
	"github.com/KarpelesLab/pktkit/vclient"
)

// UPnPConfig configures the UPnP IGD helper.
type UPnPConfig struct {
	ControlPort   uint16        // TCP port for the SOAP control server (default 5000)
	AllowedPorts  [][2]uint16   // allowed outside port ranges; empty means all
	MaxMappings   int           // max total port forwards (0 = unlimited)
	MaxPerClient  int           // max port forwards per inside IP (0 = unlimited)
	LeaseDuration time.Duration // max lease duration (0 = permanent allowed)
}

// EnableUPnP creates and registers a UPnP IGD helper on this NAT.
// Clients on the inside network can discover the NAT via SSDP and
// manage port forwarding through SOAP requests.
func (n *NAT) EnableUPnP(cfg UPnPConfig) error {
	if cfg.ControlPort == 0 {
		cfg.ControlPort = 5000
	}

	h := &upnpHelper{
		nat: n,
		cfg: cfg,
	}

	// Create a virtual client wired to the NAT's inside. Its output
	// goes through SendInside so that responses reach inside clients.
	c := vclient.New()
	h.client = c

	insideAddr := n.InsideAddr()
	ip := insideAddr.As4()
	mask := net.CIDRMask(n.inside.Addr().Bits(), 32)
	c.SetIP(net.IP(ip[:]).To4(), mask, net.IP(ip[:]).To4())

	// Wire the vclient: its outgoing packets go to the NAT inside.
	c.SetHandler(func(pkt pktkit.Packet) error {
		n.SendInside(pkt)
		return nil
	})

	// Start the HTTP/SOAP server on the vclient.
	ln, err := c.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", cfg.ControlPort))
	if err != nil {
		c.Close()
		return fmt.Errorf("upnp: listen: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", h.handleRootDesc)
	mux.HandleFunc("/ctl/WANIPConnection", h.handleSOAP)

	h.server = &http.Server{Handler: mux}
	go h.server.Serve(ln)

	n.AddHelper(h)
	return nil
}

// upnpHelper implements LocalHelper for UPnP IGD.
type upnpHelper struct {
	nat    *NAT
	cfg    UPnPConfig
	client *vclient.Client
	server *http.Server
}

func (h *upnpHelper) Name() string { return "upnp" }

func (h *upnpHelper) Close() error {
	if h.server != nil {
		h.server.Close()
	}
	if h.client != nil {
		h.client.Close()
	}
	return nil
}

// HandleLocal intercepts packets on the inside destined for the NAT's
// inside IP. It handles:
//   - SSDP M-SEARCH (UDP to 239.255.255.250:1900)
//   - TCP to the control port (forwarded to the vclient)
func (h *upnpHelper) HandleLocal(n *NAT, pkt pktkit.Packet) bool {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	proto := pkt[9]

	switch proto {
	case protoUDP:
		return h.handleUDP(n, pkt, ihl)
	case protoTCP:
		return h.handleTCP(n, pkt, ihl)
	}
	return false
}

// handleUDP checks for SSDP M-SEARCH requests.
func (h *upnpHelper) handleUDP(n *NAT, pkt pktkit.Packet, ihl int) bool {
	if len(pkt) < ihl+8 {
		return false
	}

	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != 1900 {
		return false
	}

	// Check destination IP is the SSDP multicast address 239.255.255.250.
	dstIP := netip.AddrFrom4([4]byte(pkt[16:20]))
	if dstIP != netip.MustParseAddr("239.255.255.250") {
		return false
	}

	// Parse UDP payload.
	udpLen := int(binary.BigEndian.Uint16(pkt[ihl+4 : ihl+6]))
	if udpLen < 8 || ihl+udpLen > len(pkt) {
		return false
	}
	payload := pkt[ihl+8 : ihl+udpLen]

	if !isSSDP_MSearch(payload) {
		return false
	}

	// Extract the requester's source IP and port.
	srcIP := netip.AddrFrom4([4]byte(pkt[12:16]))
	srcPort := binary.BigEndian.Uint16(pkt[ihl : ihl+2])

	// Build and send SSDP response.
	h.sendSSDPResponse(n, srcIP, srcPort)
	return true
}

// handleTCP forwards TCP packets destined for the control port to the vclient.
func (h *upnpHelper) handleTCP(n *NAT, pkt pktkit.Packet, ihl int) bool {
	if len(pkt) < ihl+4 {
		return false
	}

	dstPort := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	if dstPort != h.cfg.ControlPort {
		return false
	}

	// Forward the packet to the vclient for TCP processing.
	cp := make(pktkit.Packet, len(pkt))
	copy(cp, pkt)
	h.client.Send(cp)
	return true
}

// isSSDP_MSearch returns true if the payload looks like an SSDP M-SEARCH
// for Internet Gateway Device or ssdp:all.
func isSSDP_MSearch(payload []byte) bool {
	if !bytes.HasPrefix(payload, []byte("M-SEARCH")) {
		return false
	}
	upper := bytes.ToUpper(payload)
	if bytes.Contains(upper, []byte("SSDP:ALL")) {
		return true
	}
	if bytes.Contains(payload, []byte("urn:schemas-upnp-org:device:InternetGatewayDevice")) {
		return true
	}
	if bytes.Contains(payload, []byte("urn:schemas-upnp-org:service:WANIPConnection")) {
		return true
	}
	if bytes.Contains(payload, []byte("upnp:rootdevice")) {
		return true
	}
	return false
}

// sendSSDPResponse constructs and sends an SSDP response packet back to
// the requester via the vclient (which is wired to the inside).
func (h *upnpHelper) sendSSDPResponse(n *NAT, dstIP netip.Addr, dstPort uint16) {
	insideIP := n.InsideAddr()
	location := fmt.Sprintf("http://%s:%d/rootDesc.xml", insideIP, h.cfg.ControlPort)

	resp := "HTTP/1.1 200 OK\r\n" +
		"CACHE-CONTROL: max-age=1800\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"USN: uuid:pktkit-nat-1::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n" +
		"LOCATION: " + location + "\r\n" +
		"SERVER: pktkit/1.0 UPnP/1.1\r\n" +
		"EXT:\r\n" +
		"\r\n"
	respBytes := []byte(resp)

	// Build a raw IPv4+UDP packet from insideIP:1900 to dstIP:dstPort.
	srcIP := insideIP.As4()
	dst := dstIP.As4()
	udpPayloadLen := len(respBytes)
	udpLen := 8 + udpPayloadLen
	totalLen := 20 + udpLen

	pkt := make(pktkit.Packet, totalLen)

	// IPv4 header.
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 64 // TTL
	pkt[9] = protoUDP
	copy(pkt[12:16], srcIP[:])
	copy(pkt[16:20], dst[:])
	binary.BigEndian.PutUint16(pkt[10:12], pktkit.Checksum(pkt[:20]))

	// UDP header.
	binary.BigEndian.PutUint16(pkt[20:22], 1900)    // src port
	binary.BigEndian.PutUint16(pkt[22:24], dstPort) // dst port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
	copy(pkt[28:], respBytes)
	// UDP checksum (optional in IPv4, set to 0).
	binary.BigEndian.PutUint16(pkt[26:28], 0)

	n.SendInside(pkt)
}

// =====================================================================
// HTTP handlers
// =====================================================================

// handleRootDesc serves the UPnP device description XML.
func (h *upnpHelper) handleRootDesc(w http.ResponseWriter, r *http.Request) {
	insideIP := h.nat.InsideAddr()
	controlURL := fmt.Sprintf("http://%s:%d/ctl/WANIPConnection", insideIP, h.cfg.ControlPort)

	desc := xml.Header + fmt.Sprintf(`<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>pktkit NAT</friendlyName>
    <manufacturer>pktkit</manufacturer>
    <modelName>pktkit-nat</modelName>
    <UDN>uuid:pktkit-nat-1</UDN>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <friendlyName>WANDevice</friendlyName>
        <UDN>uuid:pktkit-nat-wan-1</UDN>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <friendlyName>WANConnectionDevice</friendlyName>
            <UDN>uuid:pktkit-nat-wanconn-1</UDN>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConnection</serviceId>
                <controlURL>%s</controlURL>
                <SCPDURL>/WANIPConnection.xml</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`, controlURL)

	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, desc)
}

// handleSOAP dispatches SOAP actions for WANIPConnection.
func (h *upnpHelper) handleSOAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	soapAction := r.Header.Get("SOAPAction")
	// Strip quotes and extract the action name after '#'.
	soapAction = strings.Trim(soapAction, "\"")
	if idx := strings.LastIndex(soapAction, "#"); idx >= 0 {
		soapAction = soapAction[idx+1:]
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	if err != nil {
		h.soapFault(w, "UPnPError", 501, "Could not read request")
		return
	}

	// Determine the client's inside IP from the TCP connection source.
	clientIP := clientIPFromRequest(r)

	switch soapAction {
	case "GetExternalIPAddress":
		h.actionGetExternalIP(w)
	case "AddPortMapping":
		h.actionAddPortMapping(w, body, clientIP)
	case "DeletePortMapping":
		h.actionDeletePortMapping(w, body)
	case "GetGenericPortMappingEntry":
		h.actionGetGenericPortMappingEntry(w, body)
	case "GetSpecificPortMappingEntry":
		h.actionGetSpecificPortMappingEntry(w, body)
	default:
		h.soapFault(w, "UPnPError", 401, "Invalid Action")
	}
}

// =====================================================================
// SOAP request/response types
// =====================================================================

// soapEnvelope is the outer SOAP envelope for request parsing.
type soapEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    soapBody `xml:"Body"`
}

type soapBody struct {
	Content []byte `xml:",innerxml"`
}

type addPortMappingRequest struct {
	XMLName                   xml.Name `xml:"AddPortMapping"`
	NewRemoteHost             string   `xml:"NewRemoteHost"`
	NewExternalPort           uint16   `xml:"NewExternalPort"`
	NewProtocol               string   `xml:"NewProtocol"`
	NewInternalPort           uint16   `xml:"NewInternalPort"`
	NewInternalClient         string   `xml:"NewInternalClient"`
	NewEnabled                int      `xml:"NewEnabled"`
	NewPortMappingDescription string   `xml:"NewPortMappingDescription"`
	NewLeaseDuration          uint32   `xml:"NewLeaseDuration"`
}

type deletePortMappingRequest struct {
	XMLName         xml.Name `xml:"DeletePortMapping"`
	NewRemoteHost   string   `xml:"NewRemoteHost"`
	NewExternalPort uint16   `xml:"NewExternalPort"`
	NewProtocol     string   `xml:"NewProtocol"`
}

type getGenericRequest struct {
	XMLName             xml.Name `xml:"GetGenericPortMappingEntry"`
	NewPortMappingIndex int      `xml:"NewPortMappingIndex"`
}

type getSpecificRequest struct {
	XMLName         xml.Name `xml:"GetSpecificPortMappingEntry"`
	NewRemoteHost   string   `xml:"NewRemoteHost"`
	NewExternalPort uint16   `xml:"NewExternalPort"`
	NewProtocol     string   `xml:"NewProtocol"`
}

// =====================================================================
// SOAP actions
// =====================================================================

func (h *upnpHelper) actionGetExternalIP(w http.ResponseWriter) {
	extIP := h.nat.OutsideAddr()
	body := fmt.Sprintf(
		`<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">`+
			`<NewExternalIPAddress>%s</NewExternalIPAddress>`+
			`</u:GetExternalIPAddressResponse>`, extIP)
	h.soapResponse(w, body)
}

func (h *upnpHelper) actionAddPortMapping(w http.ResponseWriter, body []byte, clientIP netip.Addr) {
	req, err := parseSoapAction[addPortMappingRequest](body)
	if err != nil {
		h.soapFault(w, "UPnPError", 501, "XML parse error")
		return
	}

	proto, ok := parseProtocol(req.NewProtocol)
	if !ok {
		h.soapFault(w, "UPnPError", 402, "Invalid protocol")
		return
	}

	if req.NewExternalPort == 0 {
		h.soapFault(w, "UPnPError", 716, "External port wildcard not supported")
		return
	}
	if req.NewInternalPort == 0 {
		h.soapFault(w, "UPnPError", 402, "Invalid internal port")
		return
	}

	insideIP, err := netip.ParseAddr(req.NewInternalClient)
	if err != nil || !insideIP.Is4() {
		h.soapFault(w, "UPnPError", 402, "Invalid internal client IP")
		return
	}

	// Enforce: client can only forward to itself.
	if clientIP.IsValid() && clientIP != insideIP {
		h.soapFault(w, "UPnPError", 718, "Internal client must be the requesting host")
		return
	}

	// Check allowed port ranges.
	if !h.isPortAllowed(req.NewExternalPort) {
		h.soapFault(w, "UPnPError", 718, "External port not in allowed range")
		return
	}

	// Check max mappings.
	if h.cfg.MaxMappings > 0 {
		if len(h.nat.ListPortForwards()) >= h.cfg.MaxMappings {
			h.soapFault(w, "UPnPError", 728, "Too many port mappings")
			return
		}
	}

	// Check max per client.
	if h.cfg.MaxPerClient > 0 {
		count := 0
		for _, pf := range h.nat.ListPortForwards() {
			if pf.InsideIP == insideIP {
				count++
			}
		}
		if count >= h.cfg.MaxPerClient {
			h.soapFault(w, "UPnPError", 728, "Too many port mappings for this client")
			return
		}
	}

	// Compute lease duration.
	var expires time.Time
	if req.NewLeaseDuration > 0 {
		dur := time.Duration(req.NewLeaseDuration) * time.Second
		if h.cfg.LeaseDuration > 0 && dur > h.cfg.LeaseDuration {
			dur = h.cfg.LeaseDuration
		}
		expires = time.Now().Add(dur)
	} else if h.cfg.LeaseDuration > 0 {
		expires = time.Now().Add(h.cfg.LeaseDuration)
	}
	// else: permanent (zero time)

	pf := PortForward{
		Proto:       proto,
		OutsidePort: req.NewExternalPort,
		InsideIP:    insideIP,
		InsidePort:  req.NewInternalPort,
		Description: req.NewPortMappingDescription,
		Expires:     expires,
	}
	if err := h.nat.AddPortForward(pf); err != nil {
		h.soapFault(w, "UPnPError", 501, "Failed to add port mapping")
		return
	}

	respBody := `<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:AddPortMappingResponse>`
	h.soapResponse(w, respBody)
}

func (h *upnpHelper) actionDeletePortMapping(w http.ResponseWriter, body []byte) {
	req, err := parseSoapAction[deletePortMappingRequest](body)
	if err != nil {
		h.soapFault(w, "UPnPError", 501, "XML parse error")
		return
	}

	proto, ok := parseProtocol(req.NewProtocol)
	if !ok {
		h.soapFault(w, "UPnPError", 402, "Invalid protocol")
		return
	}

	if err := h.nat.RemovePortForward(proto, req.NewExternalPort); err != nil {
		h.soapFault(w, "UPnPError", 714, "No such port mapping")
		return
	}

	respBody := `<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"></u:DeletePortMappingResponse>`
	h.soapResponse(w, respBody)
}

func (h *upnpHelper) actionGetGenericPortMappingEntry(w http.ResponseWriter, body []byte) {
	req, err := parseSoapAction[getGenericRequest](body)
	if err != nil {
		h.soapFault(w, "UPnPError", 501, "XML parse error")
		return
	}

	forwards := h.nat.ListPortForwards()
	if req.NewPortMappingIndex < 0 || req.NewPortMappingIndex >= len(forwards) {
		h.soapFault(w, "UPnPError", 713, "SpecifiedArrayIndexInvalid")
		return
	}

	pf := forwards[req.NewPortMappingIndex]
	h.soapResponse(w, portMappingEntryXML(pf, h.nat.OutsideAddr()))
}

func (h *upnpHelper) actionGetSpecificPortMappingEntry(w http.ResponseWriter, body []byte) {
	req, err := parseSoapAction[getSpecificRequest](body)
	if err != nil {
		h.soapFault(w, "UPnPError", 501, "XML parse error")
		return
	}

	proto, ok := parseProtocol(req.NewProtocol)
	if !ok {
		h.soapFault(w, "UPnPError", 402, "Invalid protocol")
		return
	}

	for _, pf := range h.nat.ListPortForwards() {
		if pf.Proto == proto && pf.OutsidePort == req.NewExternalPort {
			h.soapResponse(w, portMappingEntryXML(pf, h.nat.OutsideAddr()))
			return
		}
	}
	h.soapFault(w, "UPnPError", 714, "NoSuchEntryInArray")
}

// =====================================================================
// SOAP XML helpers
// =====================================================================

// parseSoapAction extracts the inner action element from a SOAP envelope.
func parseSoapAction[T any](body []byte) (*T, error) {
	var env soapEnvelope
	if err := xml.Unmarshal(body, &env); err != nil {
		return nil, err
	}
	var action T
	if err := xml.Unmarshal(env.Body.Content, &action); err != nil {
		return nil, err
	}
	return &action, nil
}

func (h *upnpHelper) soapResponse(w http.ResponseWriter, body string) {
	resp := xml.Header +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body>` + body + `</s:Body>` +
		`</s:Envelope>`
	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, resp)
}

func (h *upnpHelper) soapFault(w http.ResponseWriter, faultType string, code int, desc string) {
	fault := xml.Header +
		`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">` +
		`<s:Body><s:Fault><faultcode>s:Client</faultcode>` +
		`<faultstring>` + faultType + `</faultstring>` +
		`<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0">` +
		`<errorCode>` + strconv.Itoa(code) + `</errorCode>` +
		`<errorDescription>` + xmlEscape(desc) + `</errorDescription>` +
		`</UPnPError></detail></s:Fault></s:Body></s:Envelope>`
	w.Header().Set("Content-Type", "text/xml; charset=\"utf-8\"")
	w.WriteHeader(http.StatusInternalServerError)
	io.WriteString(w, fault)
}

// portMappingEntryXML formats a PortForward as a GetGenericPortMappingEntry
// or GetSpecificPortMappingEntry response body.
func portMappingEntryXML(pf PortForward, externalIP netip.Addr) string {
	protoStr := "TCP"
	if pf.Proto == protoUDP {
		protoStr = "UDP"
	}

	var leaseDur uint32
	if !pf.Expires.IsZero() {
		remaining := time.Until(pf.Expires)
		if remaining > 0 {
			leaseDur = uint32(remaining.Seconds())
		}
	}

	return fmt.Sprintf(
		`<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">`+
			`<NewRemoteHost></NewRemoteHost>`+
			`<NewExternalPort>%d</NewExternalPort>`+
			`<NewProtocol>%s</NewProtocol>`+
			`<NewInternalPort>%d</NewInternalPort>`+
			`<NewInternalClient>%s</NewInternalClient>`+
			`<NewEnabled>1</NewEnabled>`+
			`<NewPortMappingDescription>%s</NewPortMappingDescription>`+
			`<NewLeaseDuration>%d</NewLeaseDuration>`+
			`</u:GetGenericPortMappingEntryResponse>`,
		pf.OutsidePort, protoStr, pf.InsidePort, pf.InsideIP,
		xmlEscape(pf.Description), leaseDur)
}

// =====================================================================
// Utility functions
// =====================================================================

// parseProtocol converts "TCP" or "UDP" to the protocol number.
func parseProtocol(s string) (uint8, bool) {
	switch strings.ToUpper(s) {
	case "TCP":
		return protoTCP, true
	case "UDP":
		return protoUDP, true
	default:
		return 0, false
	}
}

// isPortAllowed checks whether the given outside port is within the
// configured AllowedPorts ranges. Empty AllowedPorts means all are allowed.
func (h *upnpHelper) isPortAllowed(port uint16) bool {
	if len(h.cfg.AllowedPorts) == 0 {
		return true
	}
	for _, r := range h.cfg.AllowedPorts {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

// clientIPFromRequest extracts the client's IP from the HTTP request's
// RemoteAddr field.
func clientIPFromRequest(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

// xmlEscape escapes a string for safe inclusion in XML text content.
func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}
