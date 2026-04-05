package ovpn

import (
	"crypto/sha256"
	"testing"
)

func TestPRF10Deterministic(t *testing.T) {
	secret := make([]byte, 48)
	label := []byte("test label")
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	result1 := make([]byte, 128)
	result2 := make([]byte, 128)
	prf10(result1, secret, label, seed)
	prf10(result2, secret, label, seed)

	for i := range result1 {
		if result1[i] != result2[i] {
			t.Fatalf("non-deterministic at byte %d: %d != %d", i, result1[i], result2[i])
		}
	}

	// Verify output is not all zeros
	allZero := true
	for _, b := range result1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("PRF output is all zeros")
	}
}

func TestPRF10DifferentSecrets(t *testing.T) {
	secret1 := make([]byte, 48)
	secret2 := make([]byte, 48)
	secret2[0] = 1 // differ by one byte

	label := []byte("key expansion")
	seed := make([]byte, 64)

	result1 := make([]byte, 128)
	result2 := make([]byte, 128)
	prf10(result1, secret1, label, seed)
	prf10(result2, secret2, label, seed)

	same := true
	for i := range result1 {
		if result1[i] != result2[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different secrets produced same PRF output")
	}
}

func TestPRF10DifferentLengths(t *testing.T) {
	secret := make([]byte, 48)
	label := []byte("key expansion")
	seed := make([]byte, 64)

	for _, size := range []int{48, 128, 256} {
		result := make([]byte, size)
		prf10(result, secret, label, seed)

		allZero := true
		for _, b := range result {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Fatalf("PRF output of length %d is all zeros", size)
		}
	}
}

func TestPRF12Deterministic(t *testing.T) {
	prf := prf12(sha256.New)
	secret := make([]byte, 48)
	label := []byte("test label")
	seed := make([]byte, 64)

	result1 := make([]byte, 128)
	result2 := make([]byte, 128)
	prf(result1, secret, label, seed)
	prf(result2, secret, label, seed)

	for i := range result1 {
		if result1[i] != result2[i] {
			t.Fatalf("non-deterministic at byte %d", i)
		}
	}
}

func TestSplitPreMasterSecret(t *testing.T) {
	// Even length
	secret := make([]byte, 48)
	s1, s2 := splitPreMasterSecret(secret)
	if len(s1) != 24 {
		t.Fatalf("s1 len = %d, want 24", len(s1))
	}
	if len(s2) != 24 {
		t.Fatalf("s2 len = %d, want 24", len(s2))
	}

	// Odd length — s1 and s2 overlap by 1 byte
	secret = make([]byte, 49)
	s1, s2 = splitPreMasterSecret(secret)
	if len(s1) != 25 {
		t.Fatalf("s1 len = %d, want 25", len(s1))
	}
	if len(s2) != 25 {
		t.Fatalf("s2 len = %d, want 25", len(s2))
	}
}

func TestPHashOutput(t *testing.T) {
	result := make([]byte, 32)
	secret := []byte("secret")
	seed := []byte("seed")
	pHash(result, secret, seed, sha256.New)

	allZero := true
	for _, b := range result {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("pHash produced all zeros")
	}
}
