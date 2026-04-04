package vtcp

import (
	"encoding/binary"
	"testing"
)

// buildTestSegmentBytes builds a raw TCP segment with options and 1460-byte payload.
func buildTestSegmentBytes(withOptions bool) []byte {
	var optBytes []byte
	if withOptions {
		opts := []Option{
			MSSOption(1460),
			TimestampOption(123456, 654321),
		}
		optBytes = BuildOptions(opts)
	}
	hdrLen := 20 + len(optBytes)
	payloadLen := 1460
	seg := make([]byte, hdrLen+payloadLen)
	binary.BigEndian.PutUint16(seg[0:2], 12345) // src port
	binary.BigEndian.PutUint16(seg[2:4], 80)    // dst port
	binary.BigEndian.PutUint32(seg[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(seg[8:12], 2000) // ack
	seg[12] = byte(hdrLen/4) << 4               // data offset
	seg[13] = FlagACK                           // flags
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	if len(optBytes) > 0 {
		copy(seg[20:], optBytes)
	}
	// Fill payload with pattern.
	for i := hdrLen; i < len(seg); i++ {
		seg[i] = byte(i)
	}
	return seg
}

func BenchmarkParseSegment(b *testing.B) {
	raw := buildTestSegmentBytes(true)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSegment(raw)
	}
}

func BenchmarkParseSegmentNoOptions(b *testing.B) {
	raw := buildTestSegmentBytes(false)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseSegment(raw)
	}
}

func BenchmarkMarshalSegment(b *testing.B) {
	raw := buildTestSegmentBytes(true)
	seg, _ := ParseSegment(raw)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = seg.Marshal()
	}
}

func BenchmarkMarshalSegmentNoOptions(b *testing.B) {
	raw := buildTestSegmentBytes(false)
	seg, _ := ParseSegment(raw)
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = seg.Marshal()
	}
}

// --- SendBuf benchmarks ---

func BenchmarkSendBufWrite(b *testing.B) {
	data := make([]byte, 1460)
	for i := range data {
		data[i] = byte(i)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := NewSendBuf(1<<20, 0) // 1 MB
		buf.Write(data)
	}
}

func BenchmarkSendBufWriteAcknowledge(b *testing.B) {
	data := make([]byte, 1460)
	buf := NewSendBuf(1<<20, 0)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Write(data)
		buf.AdvanceSent(len(data))
		buf.Acknowledge(buf.NXT())
	}
}

func BenchmarkSendBufPeekUnsent(b *testing.B) {
	data := make([]byte, 1460)
	buf := NewSendBuf(1<<20, 0)
	buf.Write(data)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buf.PeekUnsent(1460)
	}
}

// --- RecvBuf benchmarks ---

func BenchmarkRecvBufInsertInOrder(b *testing.B) {
	data := make([]byte, 1460)
	for i := range data {
		data[i] = byte(i)
	}
	readBuf := make([]byte, 1460)
	b.ReportAllocs()
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := NewRecvBuf(0, 1<<20)
		buf.Insert(0, data)
		buf.Read(readBuf)
	}
}

func BenchmarkRecvBufInsertOOO(b *testing.B) {
	seg1 := make([]byte, 1460)
	seg2 := make([]byte, 1460)
	for i := range seg1 {
		seg1[i] = byte(i)
		seg2[i] = byte(i + 100)
	}
	readBuf := make([]byte, 2920)
	b.ReportAllocs()
	b.SetBytes(int64(len(seg1) + len(seg2)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := NewRecvBuf(0, 1<<20)
		// Insert segment 2 first (out of order), then segment 1.
		buf.Insert(1460, seg2)
		buf.Insert(0, seg1)
		buf.Read(readBuf)
	}
}

func BenchmarkRecvBufRead(b *testing.B) {
	data := make([]byte, 1460)
	readBuf := make([]byte, 1460)
	buf := NewRecvBuf(0, 1<<20)
	seq := uint32(0)
	// Fill buffer with enough data.
	for j := 0; j < 100; j++ {
		buf.Insert(seq, data)
		seq += uint32(len(data))
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(readBuf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if buf.Readable() < len(readBuf) {
			// Refill.
			buf.Insert(seq, data)
			seq += uint32(len(data))
		}
		buf.Read(readBuf)
	}
}

// --- Options benchmarks ---

func BenchmarkBuildOptions(b *testing.B) {
	opts := []Option{
		MSSOption(1460),
		WScaleOption(7),
		SACKPermOption(),
		TimestampOption(123456, 654321),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildOptions(opts)
	}
}

func BenchmarkParseOptions(b *testing.B) {
	opts := BuildOptions([]Option{
		MSSOption(1460),
		WScaleOption(7),
		SACKPermOption(),
		TimestampOption(123456, 654321),
	})
	b.ReportAllocs()
	b.SetBytes(int64(len(opts)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ParseOptions(opts)
	}
}
