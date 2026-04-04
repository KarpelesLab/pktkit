package pktkit

// ConnectL2 wires two L2Devices in a point-to-point link: frames produced
// by one are delivered to the other.
func ConnectL2(a, b L2Device) {
	a.SetHandler(func(f Frame) { b.Send(f) })
	b.SetHandler(func(f Frame) { a.Send(f) })
}

// ConnectL3 wires two L3Devices in a point-to-point link: packets produced
// by one are delivered to the other.
func ConnectL3(a, b L3Device) {
	a.SetHandler(func(p Packet) { b.Send(p) })
	b.SetHandler(func(p Packet) { a.Send(p) })
}
