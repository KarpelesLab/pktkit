package ovpn

import (
	"encoding/hex"
	"log"
)

type PeerKeys struct {
	CipherEncrypt []byte
	HmacEncrypt   []byte
	CipherDecrypt []byte
	HmacDecrypt   []byte
}

func NewPeerKeys(main []byte) *PeerKeys {
	if len(main) != 256 {
		panic("invalid length for peer keys master")
	}
	res := new(PeerKeys)
	res.CipherEncrypt = make([]byte, 64)
	res.HmacEncrypt = make([]byte, 64)
	res.CipherDecrypt = make([]byte, 64)
	res.HmacDecrypt = make([]byte, 64)

	// server side order (client side reverses decrypt/encrypt)
	copy(res.CipherDecrypt, main[0:64])
	copy(res.HmacDecrypt, main[64:128])
	copy(res.CipherEncrypt, main[128:192])
	copy(res.HmacEncrypt, main[192:256])

	return res
}

func (pk *PeerKeys) Dump() {
	log.Printf("[debug] Master Encrypt (cipher): %s...", hex.EncodeToString(pk.CipherEncrypt[0:4]))
	log.Printf("[debug] Master Encrypt (hmac): %s...", hex.EncodeToString(pk.HmacEncrypt[0:4]))
	log.Printf("[debug] Master Decrypt (cipher): %s...", hex.EncodeToString(pk.CipherDecrypt[0:4]))
	log.Printf("[debug] Master Decrypt (hmac): %s...", hex.EncodeToString(pk.HmacDecrypt[0:4]))
}

func (pk *PeerKeys) Clear() {
	// optimized memset: https://codereview.appspot.com/137880043
	for i := range pk.CipherEncrypt {
		pk.CipherEncrypt[i] = 0
	}
	for i := range pk.HmacEncrypt {
		pk.HmacEncrypt[i] = 0
	}
	for i := range pk.CipherDecrypt {
		pk.CipherDecrypt[i] = 0
	}
	for i := range pk.HmacDecrypt {
		pk.HmacDecrypt[i] = 0
	}
}
