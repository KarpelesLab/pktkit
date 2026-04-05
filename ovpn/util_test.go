package ovpn

import (
	"crypto/rand"
	"io"
	"net"
	"testing"
)

func TestPKCS5PaddingBlockAligned(t *testing.T) {
	// Input length is a multiple of block size — should add full block of padding.
	input := make([]byte, 16)
	padded := PKCS5Padding(input, 16)
	if len(padded) != 32 {
		t.Fatalf("expected len 32, got %d", len(padded))
	}
	for i := 16; i < 32; i++ {
		if padded[i] != 16 {
			t.Fatalf("expected padding byte 16 at %d, got %d", i, padded[i])
		}
	}
}

func TestPKCS5PaddingUnaligned(t *testing.T) {
	input := make([]byte, 13)
	padded := PKCS5Padding(input, 16)
	if len(padded) != 16 {
		t.Fatalf("expected len 16, got %d", len(padded))
	}
	for i := 13; i < 16; i++ {
		if padded[i] != 3 {
			t.Fatalf("expected padding byte 3 at %d, got %d", i, padded[i])
		}
	}
}

func TestPKCS5TrimmingRoundtrip(t *testing.T) {
	for _, size := range []int{1, 7, 15, 16, 31, 33} {
		input := make([]byte, size)
		for i := range input {
			input[i] = byte(i)
		}
		padded := PKCS5Padding(input, 16)
		trimmed := PKCS5Trimming(padded)
		if len(trimmed) != size {
			t.Fatalf("size %d: expected len %d after trim, got %d", size, size, len(trimmed))
		}
		for i := range input {
			if trimmed[i] != input[i] {
				t.Fatalf("size %d: byte %d mismatch", size, i)
			}
		}
	}
}

func TestPeerKeysNew(t *testing.T) {
	material := make([]byte, 256)
	for i := range material {
		material[i] = byte(i)
	}

	keys := NewPeerKeys(material)
	// CipherDecrypt = [0:64], HmacDecrypt = [64:128]
	// CipherEncrypt = [128:192], HmacEncrypt = [192:256]
	for i := 0; i < 64; i++ {
		if keys.CipherDecrypt[i] != byte(i) {
			t.Fatalf("CipherDecrypt[%d] = %d, want %d", i, keys.CipherDecrypt[i], byte(i))
		}
		if keys.HmacDecrypt[i] != byte(64+i) {
			t.Fatalf("HmacDecrypt[%d] = %d, want %d", i, keys.HmacDecrypt[i], byte(64+i))
		}
		if keys.CipherEncrypt[i] != byte(128+i) {
			t.Fatalf("CipherEncrypt[%d] = %d, want %d", i, keys.CipherEncrypt[i], byte(128+i))
		}
		if keys.HmacEncrypt[i] != byte(192+i) {
			t.Fatalf("HmacEncrypt[%d] = %d, want %d", i, keys.HmacEncrypt[i], byte(192+i))
		}
	}
}

func TestPeerKeysClear(t *testing.T) {
	material := make([]byte, 256)
	if _, err := io.ReadFull(rand.Reader, material); err != nil {
		t.Fatal(err)
	}
	keys := NewPeerKeys(material)
	keys.Clear()

	for i := range keys.CipherEncrypt {
		if keys.CipherEncrypt[i] != 0 || keys.HmacEncrypt[i] != 0 ||
			keys.CipherDecrypt[i] != 0 || keys.HmacDecrypt[i] != 0 {
			t.Fatalf("key material not zeroed at index %d", i)
		}
	}
}

func TestPeerKeysNewPanicOnBadLen(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid key length")
		}
	}()
	NewPeerKeys(make([]byte, 128))
}

func TestAddrKeyTCP(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
	key, err := addrKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	// Protocol byte should be 0x02 (TCP)
	if key[16] != 0x02 {
		t.Fatalf("expected proto byte 0x02, got 0x%02x", key[16])
	}
	// Port = 443 = 0x01BB
	if key[17] != 0x01 || key[18] != 0xBB {
		t.Fatalf("expected port 443 encoded, got 0x%02x%02x", key[17], key[18])
	}
}

func TestAddrKeyUDP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 1194}
	key, err := addrKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	if key[16] != 0x01 {
		t.Fatalf("expected proto byte 0x01 (UDP), got 0x%02x", key[16])
	}
}

func TestAddrKeyInvalid(t *testing.T) {
	_, err := addrKey(&net.UnixAddr{Name: "/tmp/test"})
	if err == nil {
		t.Fatal("expected error for unsupported address type")
	}
}

func TestAddrStringTCP(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8080}
	key, _ := addrKey(addr)
	s := key.String()
	if s[:4] != "tcp/" {
		t.Fatalf("expected tcp/ prefix, got %q", s)
	}
}

func TestAddrStringUDP(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1194}
	key, _ := addrKey(addr)
	s := key.String()
	if s[:4] != "udp/" {
		t.Fatalf("expected udp/ prefix, got %q", s)
	}
}

func TestAddrTCPAddrRoundtrip(t *testing.T) {
	orig := &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1).To16(), Port: 12345}
	key, _ := addrKey(orig)
	got := key.TCPAddr()
	if got.Port != 12345 {
		t.Fatalf("port mismatch: %d != 12345", got.Port)
	}
}

func TestAddrKeyIPv6(t *testing.T) {
	addr := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 443}
	key, err := addrKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	if key[16] != 0x02 {
		t.Fatalf("expected proto byte 0x02 (TCP), got 0x%02x", key[16])
	}
}
