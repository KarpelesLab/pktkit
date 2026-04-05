package ovpn

import (
	"crypto"
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
)

// V4,dev-type tun,link-mtu 1570,tun-mtu 1500,proto UDPv4,comp-lzo,cipher AES-128-CBC,auth SHA256,keysize 128,key-method 2,tls-client
type Options struct {
	Version         int // 4
	IsServer        bool
	DevType         string // "tun" or "tap"
	LinkMtu, TunMtu uint64
	Proto           string            // "UDPv4", etc
	Compression     string            // "" "lzo" "lz4"
	CipherCrypto    CipherCryptoAlg   // AES
	CipherSize      int               // 128|256
	CipherBlock     CipherBlockMethod // CBC|GCM
	Auth            crypto.Hash       // hmac algo, for example "SHA256"
	KeySize         uint64            // 128
	KeyMethod       uint64            // 2

	// generated local values for faster processing
	AuthHashSize int
	AuthHashNew  func() hash.Hash

	CipherBlockDecrypt cipher.Block
	CipherBlockEncrypt cipher.Block

	DecryptAEAD cipher.AEAD
	EncryptAEAD cipher.AEAD
}

func NewOptions() *Options {
	res := &Options{
		Version:      4,
		IsServer:     true,
		DevType:      "tun",
		LinkMtu:      1500,
		TunMtu:       1500 - 70,
		Proto:        "UDPv4",
		Compression:  "lzo",
		CipherCrypto: AES,
		CipherSize:   128,
		CipherBlock:  CBC,
		Auth:         crypto.SHA256,
		KeySize:      128,
		KeyMethod:    2,
	}

	res.Prepare()

	return res
}

func (o *Options) Parse(s string) (err error) {
	s_split := strings.Split(s, ",")

	if s_split[0] != "V4" {
		err = errors.New("expected V4 options string")
		return
	}

	s_split = s_split[1:]

	// we don't care about parsing all options, since check will happen afterward comparing string with result
	for _, opt := range s_split {
		pos := strings.IndexByte(opt, ' ')
		var k, v string
		if pos >= 0 {
			k = opt[:pos]
			v = opt[pos+1:]
		} else {
			k = opt
			v = ""
		}

		switch k {
		case "dev-type":
			switch v {
			case "tun":
			case "tap":
			default:
				return errors.New("invalid dev-type in options string")
			}
			o.DevType = v
		case "link-mtu":
			o.LinkMtu, err = strconv.ParseUint(v, 10, 32)
		case "tun-mtu":
			o.TunMtu, err = strconv.ParseUint(v, 10, 32)
		case "proto":
			o.Proto = v
		case "cipher":
			err = o.ParseCipher(v)
		case "auth":
			o.Auth, err = optionHashParse(v)
		case "keysize":
			o.KeySize, err = strconv.ParseUint(v, 10, 32)
		case "key-method":
			o.KeyMethod, err = strconv.ParseUint(v, 10, 8)
		}
		if err != nil {
			return
		}
	}

	err = o.Prepare()

	return
}

func (o *Options) Prepare() error {
	if o.Auth == 0 {
		o.AuthHashSize = 0
	} else {
		if !o.Auth.Available() {
			return errors.New("requested auth algo is not available")
		}
		o.AuthHashSize = o.Auth.Size()
		o.AuthHashNew = o.Auth.New
	}

	o.CipherBlockDecrypt = nil
	o.CipherBlockEncrypt = nil

	o.DecryptAEAD = nil
	o.EncryptAEAD = nil
	return nil
}

func (o *Options) String() string {
	// generate string out of options
	// openvpn, options.c, options_string()

	res := fmt.Sprintf("V%d", o.Version)
	res += ",dev-type " + o.DevType
	res += fmt.Sprintf(",link-mtu %d", o.LinkMtu)
	res += fmt.Sprintf(",tun-mtu %d", o.TunMtu)
	res += ",proto " + o.Proto

	// ifconfig

	if o.Compression != "none" {
		res += ",comp-lzo"
	}
	// mtu-dynamic
	if o.CipherCrypto == 0 {
		res += ",cipher [null-cipher]"
	} else {
		res += fmt.Sprintf(",cipher %s-%d-%s", o.CipherCrypto.String(), o.CipherSize, o.CipherBlock.String())
	}
	res += ",auth " + o.HashString()
	res += fmt.Sprintf(",keysize %d", o.KeySize)
	// secret
	// no-replay
	// tls-auth
	res += fmt.Sprintf(",key-method %d", o.KeyMethod)

	if o.IsServer {
		res += ",tls-server"
	} else {
		res += ",tls-client"
	}

	return res
}

func (o *Options) ParseCipher(c string) error {
	if c == "[null-cipher]" {
		o.CipherCrypto = 0
		return nil
	}

	info := strings.Split(c, "-")

	if info[0] != "AES" {
		return errors.New("only AES is supported")
	}

	o.CipherCrypto = AES

	switch info[1] {
	case "128":
		o.CipherSize = 128
	case "256":
		o.CipherSize = 256
	default:
		return errors.New("invalid cipher block size")
	}

	switch info[2] {
	case "CBC":
		o.CipherBlock = CBC
	case "GCM":
		o.CipherBlock = GCM
	default:
		return errors.New("invalid cipher block mode")
	}

	return nil
}

func optionHashParse(s string) (crypto.Hash, error) {
	switch s {
	case "[null-digest]":
		return 0, nil
	case "SHA1":
		return crypto.SHA1, nil
	case "SHA224":
		return crypto.SHA224, nil
	case "SHA256":
		return crypto.SHA256, nil
	}
	return 0, errors.New("unrecognized crypto hash")
}

func (o *Options) HashString() string {
	switch o.Auth {
	case 0:
		return "[null-digest]"
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA224:
		return "SHA224"
	case crypto.SHA256:
		return "SHA256"
	}
	return "???"
}
