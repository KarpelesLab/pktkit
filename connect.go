package pktkit

// ConnectL2 wires two L2Devices in a point-to-point link: frames produced
// by one are delivered to the other.
func ConnectL2(a, b L2Device) {
	a.SetHandler(b.Send)
	b.SetHandler(a.Send)
}

// ConnectL3 wires two L3Devices in a point-to-point link: packets produced
// by one are delivered to the other.
func ConnectL3(a, b L3Device) {
	a.SetHandler(b.Send)
	b.SetHandler(a.Send)
}
