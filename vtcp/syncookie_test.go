package vtcp

import (
	"testing"
)

func TestSYNCookieRoundTrip(t *testing.T) {
	sc := NewSYNCookies()

	syn := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000000,
		Flags:   FlagSYN,
		Window:  65535,
	}

	synack := sc.GenerateSYNACK(syn, 80, 1460)

	// Verify SYN-ACK structure.
	if synack.SrcPort != 80 {
		t.Errorf("SrcPort = %d, want 80", synack.SrcPort)
	}
	if synack.DstPort != 12345 {
		t.Errorf("DstPort = %d, want 12345", synack.DstPort)
	}
	if synack.Ack != syn.Seq+1 {
		t.Errorf("Ack = %d, want %d", synack.Ack, syn.Seq+1)
	}
	if synack.Flags != FlagSYN|FlagACK {
		t.Errorf("Flags = %02x, want SYN|ACK", synack.Flags)
	}

	// Simulate client's ACK completing the handshake.
	ack := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     syn.Seq + 1,
		Ack:     synack.Seq + 1,
		Flags:   FlagACK,
		Window:  65535,
	}

	mss, remoteISN, ok := sc.ValidateACK(ack, 80)
	if !ok {
		t.Fatal("ValidateACK returned false for valid cookie")
	}
	if remoteISN != syn.Seq {
		t.Errorf("remoteISN = %d, want %d", remoteISN, syn.Seq)
	}
	if mss != 1460 {
		t.Errorf("MSS = %d, want 1460", mss)
	}
}

func TestSYNCookieInvalid(t *testing.T) {
	sc := NewSYNCookies()

	// Random ACK with no corresponding SYN cookie.
	ack := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     5000,
		Ack:     99999,
		Flags:   FlagACK,
	}
	_, _, ok := sc.ValidateACK(ack, 80)
	if ok {
		t.Error("ValidateACK should reject random ACK")
	}
}

func TestSYNCookieTamperedACK(t *testing.T) {
	sc := NewSYNCookies()

	syn := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000000,
		Flags:   FlagSYN,
	}
	synack := sc.GenerateSYNACK(syn, 80, 1460)

	// Tamper with the ACK number (flip a bit in the hash portion).
	ack := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     syn.Seq + 1,
		Ack:     synack.Seq + 1 ^ 0x00010000, // flip bit in hash
		Flags:   FlagACK,
	}
	_, _, ok := sc.ValidateACK(ack, 80)
	if ok {
		t.Error("ValidateACK should reject tampered ACK")
	}
}

func TestSYNCookieWrongPort(t *testing.T) {
	sc := NewSYNCookies()

	syn := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000000,
		Flags:   FlagSYN,
	}
	synack := sc.GenerateSYNACK(syn, 80, 1460)

	ack := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     syn.Seq + 1,
		Ack:     synack.Seq + 1,
		Flags:   FlagACK,
	}

	// Validate with wrong local port.
	_, _, ok := sc.ValidateACK(ack, 8080)
	if ok {
		t.Error("ValidateACK should reject ACK validated against wrong port")
	}
}

func TestSYNCookieMSSPreservation(t *testing.T) {
	sc := NewSYNCookies()

	for _, wantMSS := range mssTable {
		syn := Segment{
			SrcPort: 12345,
			DstPort: 80,
			Seq:     2000000,
			Flags:   FlagSYN,
		}
		synack := sc.GenerateSYNACK(syn, 80, wantMSS)

		ack := Segment{
			SrcPort: 12345,
			DstPort: 80,
			Seq:     syn.Seq + 1,
			Ack:     synack.Seq + 1,
			Flags:   FlagACK,
		}

		mss, _, ok := sc.ValidateACK(ack, 80)
		if !ok {
			t.Errorf("ValidateACK failed for MSS %d", wantMSS)
			continue
		}
		if mss != wantMSS {
			t.Errorf("MSS = %d, want %d", mss, wantMSS)
		}
	}
}

func TestSYNCookieNoACKFlag(t *testing.T) {
	sc := NewSYNCookies()

	seg := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     5000,
		Flags:   FlagSYN, // no ACK flag
	}
	_, _, ok := sc.ValidateACK(seg, 80)
	if ok {
		t.Error("ValidateACK should reject segments without ACK flag")
	}
}

func TestSYNCookieMultipleClients(t *testing.T) {
	sc := NewSYNCookies()

	// Simulate multiple concurrent clients.
	type client struct {
		srcPort uint16
		seq     uint32
	}
	clients := []client{
		{12345, 100000},
		{54321, 200000},
		{11111, 300000},
		{22222, 400000},
	}

	synacks := make([]Segment, len(clients))
	for i, cl := range clients {
		syn := Segment{SrcPort: cl.srcPort, DstPort: 80, Seq: cl.seq, Flags: FlagSYN}
		synacks[i] = sc.GenerateSYNACK(syn, 80, 1460)
	}

	// Validate each client's ACK.
	for i, cl := range clients {
		ack := Segment{
			SrcPort: cl.srcPort,
			DstPort: 80,
			Seq:     cl.seq + 1,
			Ack:     synacks[i].Seq + 1,
			Flags:   FlagACK,
		}
		mss, remoteISN, ok := sc.ValidateACK(ack, 80)
		if !ok {
			t.Errorf("client %d: ValidateACK failed", i)
			continue
		}
		if remoteISN != cl.seq {
			t.Errorf("client %d: remoteISN = %d, want %d", i, remoteISN, cl.seq)
		}
		if mss != 1460 {
			t.Errorf("client %d: MSS = %d, want 1460", i, mss)
		}
	}
}

func TestSYNCookieAcceptCookie(t *testing.T) {
	sc := NewSYNCookies()

	syn := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     1000000,
		Flags:   FlagSYN,
	}
	synack := sc.GenerateSYNACK(syn, 80, 1460)

	ack := Segment{
		SrcPort: 12345,
		DstPort: 80,
		Seq:     syn.Seq + 1,
		Ack:     synack.Seq + 1,
		Flags:   FlagACK,
	}

	mss, _, ok := sc.ValidateACK(ack, 80)
	if !ok {
		t.Fatal("ValidateACK failed")
	}

	// Create a Conn via AcceptCookie.
	var sent [][]byte
	conn := NewConn(ConnConfig{
		LocalPort:  80,
		RemotePort: 12345,
		MSS:        1460,
		Writer: func(seg []byte) error {
			cp := make([]byte, len(seg))
			copy(cp, seg)
			sent = append(sent, cp)
			return nil
		},
	})

	pkts := conn.AcceptCookie(ack.Seq, synack.Seq, mss, nil)
	if len(pkts) == 0 {
		t.Fatal("AcceptCookie should return an ACK")
	}

	if conn.State() != StateEstablished {
		t.Errorf("state = %v, want Established", conn.State())
	}

	// Verify we can write data.
	n, err := conn.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != 5 {
		t.Errorf("Write returned %d, want 5", n)
	}
}

// --- Benchmarks ---

func BenchmarkSYNCookieGenerate(b *testing.B) {
	sc := NewSYNCookies()
	syn := Segment{SrcPort: 12345, DstPort: 80, Seq: 1000000, Flags: FlagSYN}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sc.GenerateSYNACK(syn, 80, 1460)
	}
}

func BenchmarkSYNCookieValidate(b *testing.B) {
	sc := NewSYNCookies()
	syn := Segment{SrcPort: 12345, DstPort: 80, Seq: 1000000, Flags: FlagSYN}
	synack := sc.GenerateSYNACK(syn, 80, 1460)
	ack := Segment{SrcPort: 12345, DstPort: 80, Seq: syn.Seq + 1, Ack: synack.Seq + 1, Flags: FlagACK}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = sc.ValidateACK(ack, 80)
	}
}

func BenchmarkSYNCookieValidateInvalid(b *testing.B) {
	sc := NewSYNCookies()
	ack := Segment{SrcPort: 12345, DstPort: 80, Seq: 5000, Ack: 99999, Flags: FlagACK}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = sc.ValidateACK(ack, 80)
	}
}
