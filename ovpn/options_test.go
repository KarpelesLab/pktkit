package ovpn

import (
	"crypto"
	"testing"
)

func TestOptionsCipherParsing(t *testing.T) {
	tests := []struct {
		cipher string
		crypto CipherCryptoAlg
		size   int
		block  CipherBlockMethod
	}{
		{"AES-128-CBC", AES, 128, CBC},
		{"AES-256-CBC", AES, 256, CBC},
		{"AES-128-GCM", AES, 128, GCM},
		{"AES-256-GCM", AES, 256, GCM},
	}

	for _, tc := range tests {
		o := &Options{}
		if err := o.ParseCipher(tc.cipher); err != nil {
			t.Errorf("ParseCipher(%q) failed: %v", tc.cipher, err)
			continue
		}
		if o.CipherCrypto != tc.crypto {
			t.Errorf("ParseCipher(%q): crypto = %v, want %v", tc.cipher, o.CipherCrypto, tc.crypto)
		}
		if o.CipherSize != tc.size {
			t.Errorf("ParseCipher(%q): size = %d, want %d", tc.cipher, o.CipherSize, tc.size)
		}
		if o.CipherBlock != tc.block {
			t.Errorf("ParseCipher(%q): block = %v, want %v", tc.cipher, o.CipherBlock, tc.block)
		}
	}
}

func TestOptionsCipherNull(t *testing.T) {
	o := &Options{}
	if err := o.ParseCipher("[null-cipher]"); err != nil {
		t.Fatal(err)
	}
	if o.CipherCrypto != 0 {
		t.Fatalf("expected null cipher (0), got %v", o.CipherCrypto)
	}
}

func TestOptionsCipherInvalid(t *testing.T) {
	tests := []string{
		"RSA-256-CBC",     // unsupported algorithm
		"AES-512-CBC",     // invalid size
		"AES-256-CTR",     // invalid mode
		"AES-256",         // missing mode
		"AES",             // too few parts
		"",                // empty
		"AES-128-CBC-SHA", // too many parts
	}

	for _, cipher := range tests {
		o := &Options{}
		if err := o.ParseCipher(cipher); err == nil {
			t.Errorf("ParseCipher(%q) should have failed", cipher)
		}
	}
}

func TestOptionsHashParsing(t *testing.T) {
	tests := []struct {
		input string
		want  crypto.Hash
	}{
		{"[null-digest]", 0},
		{"SHA1", crypto.SHA1},
		{"SHA224", crypto.SHA224},
		{"SHA256", crypto.SHA256},
	}

	for _, tc := range tests {
		got, err := optionHashParse(tc.input)
		if err != nil {
			t.Errorf("optionHashParse(%q) failed: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("optionHashParse(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestOptionsHashInvalid(t *testing.T) {
	_, err := optionHashParse("MD5")
	if err == nil {
		t.Fatal("expected error for unsupported hash")
	}
}

func TestOptionsHashString(t *testing.T) {
	tests := []struct {
		hash crypto.Hash
		want string
	}{
		{0, "[null-digest]"},
		{crypto.SHA1, "SHA1"},
		{crypto.SHA224, "SHA224"},
		{crypto.SHA256, "SHA256"},
		{crypto.SHA512, "???"},
	}

	for _, tc := range tests {
		o := &Options{Auth: tc.hash}
		got := o.HashString()
		if got != tc.want {
			t.Errorf("HashString() for %v = %q, want %q", tc.hash, got, tc.want)
		}
	}
}

func TestOptionsParseInvalidVersion(t *testing.T) {
	o := NewOptions()
	if err := o.Parse("V3,dev-type tun"); err == nil {
		t.Fatal("expected error for V3")
	}
}

func TestOptionsParseInvalidDevType(t *testing.T) {
	o := NewOptions()
	if err := o.Parse("V4,dev-type bridge"); err == nil {
		t.Fatal("expected error for invalid dev-type")
	}
}

func TestOptionsRoundtrip(t *testing.T) {
	optStr := "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto TCPv4_SERVER,comp-lzo,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-server"
	o1 := NewOptions()
	if err := o1.Parse(optStr); err != nil {
		t.Fatal(err)
	}

	s := o1.String()
	o2 := NewOptions()
	if err := o2.Parse(s); err != nil {
		t.Fatal("re-parse failed:", err)
	}

	if o1.CipherCrypto != o2.CipherCrypto || o1.CipherSize != o2.CipherSize ||
		o1.CipherBlock != o2.CipherBlock || o1.Auth != o2.Auth ||
		o1.KeySize != o2.KeySize || o1.KeyMethod != o2.KeyMethod ||
		o1.DevType != o2.DevType || o1.IsServer != o2.IsServer {
		t.Fatal("roundtrip mismatch")
	}
}

func TestOptionsNewDefaults(t *testing.T) {
	o := NewOptions()
	if o.Version != 4 {
		t.Fatalf("expected version 4, got %d", o.Version)
	}
	if o.CipherCrypto != AES {
		t.Fatalf("expected AES cipher, got %v", o.CipherCrypto)
	}
	if o.CipherBlock != CBC {
		t.Fatalf("expected CBC mode, got %v", o.CipherBlock)
	}
	if o.Auth != crypto.SHA256 {
		t.Fatalf("expected SHA256 auth, got %v", o.Auth)
	}
}

func TestOptionsDevTypeTun(t *testing.T) {
	o := NewOptions()
	if err := o.Parse("V4,dev-type tun"); err != nil {
		t.Fatal(err)
	}
	if o.DevType != "tun" {
		t.Fatalf("expected tun, got %q", o.DevType)
	}
}

func TestOptionsDevTypeTap(t *testing.T) {
	o := NewOptions()
	if err := o.Parse("V4,dev-type tap"); err != nil {
		t.Fatal(err)
	}
	if o.DevType != "tap" {
		t.Fatalf("expected tap, got %q", o.DevType)
	}
}

func TestOptionsStringClient(t *testing.T) {
	o := NewOptions()
	o.IsServer = false
	s := o.String()
	if s[len(s)-10:] != "tls-client" {
		t.Fatalf("expected tls-client suffix, got %q", s)
	}
}

func TestOptionsParseCBC(t *testing.T) {
	o := NewOptions()
	err := o.Parse("V4,dev-type tun,link-mtu 1570,tun-mtu 1500,proto UDPv4,comp-lzo,cipher AES-128-CBC,auth SHA256,keysize 128,key-method 2,tls-client")
	if err != nil {
		t.Fatal(err)
	}
	if o.CipherBlock != CBC {
		t.Fatalf("expected CBC, got %v", o.CipherBlock)
	}
	if o.Auth != crypto.SHA256 {
		t.Fatalf("expected SHA256, got %v", o.Auth)
	}
}
