package ovpn

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"strings"
)

func (p *Peer) tlsThread() {
	err := p.tlsConn.Handshake()
	if err != nil {
		log.Printf("[ovpn] tls handshake failed: %v", err)
		p.Close()
		return
	}

	err = p.ovpnControl()
	if err != nil {
		log.Printf("[ovpn] control channel process failed: %v", err)
		errMsg := strings.Map(func(r rune) rune {
			if r < 32 {
				return -1
			}
			return r
		}, err.Error())
		p.tlsConn.Write([]byte("AUTH_FAILED," + errMsg + "\x00"))
	}
	p.tlsConn.Close()

	p.Close()
}

func (p *Peer) ovpnControl() error {
	var zero uint32
	binary.Read(p.tlsConn, binary.BigEndian, &zero)
	if zero != 0 {
		return errors.New("control channel failed, expected 4 zero bytes in control stream start")
	}

	var key_method uint8
	binary.Read(p.tlsConn, binary.BigEndian, &key_method)

	if key_method&KEY_METHOD_MASK != 2 {
		return errors.New("invalid key method, expected method 2")
	}

	// read from client the following
	pre_master := make([]byte, 48)
	random1 := make([]byte, 32)
	random2 := make([]byte, 32)

	_, err := io.ReadFull(p.tlsConn, pre_master)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(p.tlsConn, random1)
	if err != nil {
		return err
	}
	_, err = io.ReadFull(p.tlsConn, random2)
	if err != nil {
		return err
	}

	// read options string
	options_string, err := p.readControlString()
	if err != nil {
		return err
	}

	opt := NewOptions()
	err = opt.Parse(options_string)
	if err != nil {
		return err
	}
	opt.IsServer = false
	if opt.String() != options_string {
		return errors.New("invalid options provided")
	}

	p.opts = opt

	// read login/pass (if disabled, both will be empty strings)
	auth_user, err := p.readControlString()
	if err != nil {
		return err
	}
	auth_pass, err := p.readControlString()
	if err != nil {
		return err
	}

	// read peer info
	peer_info, err := p.readControlString()
	if err != nil {
		return err
	}
	peer_info_split := strings.Split(peer_info, "\n")
	peer_info_map := make(map[string]string)
	for _, s := range peer_info_split {
		if s == "" {
			continue
		}
		pos := strings.IndexByte(s, '=')
		if pos < 0 {
			return errors.New("invalid string in peer_info")
		}
		peer_info_map[s[:pos]] = s[pos+1:]
	}

	// let's prepare to act as server!

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint32(0))
	binary.Write(buf, binary.BigEndian, uint8(2)) // key_method

	// gather random bytes
	server_random1 := make([]byte, 32)
	server_random2 := make([]byte, 32)
	io.ReadFull(rand.Reader, server_random1)
	io.ReadFull(rand.Reader, server_random2)
	buf.Write(server_random1)
	buf.Write(server_random2)

	opt.IsServer = true
	writeControlStringBuf(buf, opt.String())
	writeControlStringBuf(buf, "") // username
	writeControlStringBuf(buf, "") // password

	writeControlStringBuf(buf, peer_info)

	bufbytes := buf.Bytes()
	if _, err := p.tlsConn.Write(bufbytes); err != nil {
		return err
	}
	for i := range bufbytes {
		bufbytes[i] = 0
	}

	// generate master key
	master_key := make([]byte, 48)
	prf10(master_key, pre_master, []byte(KEY_EXPANSION_ID+" master secret"), bytes.Join([][]byte{random1, server_random1}, []byte{}))

	// memclr secrets
	for i := range random1 {
		random1[i] = 0
	}
	for i := range server_random1 {
		server_random1[i] = 0
	}
	for i := range pre_master {
		pre_master[i] = 0
	}

	// generate expansion
	crypt_keys := make([]byte, 256)
	prf10(crypt_keys, master_key, []byte(KEY_EXPANSION_ID+" key expansion"), bytes.Join([][]byte{random2, server_random2, p.peerId[:], p.localId[:]}, []byte{}))

	// memclr secrets
	for i := range random2 {
		random2[i] = 0
	}
	for i := range server_random2 {
		server_random2[i] = 0
	}
	for i := range master_key {
		master_key[i] = 0
	}

	p.keys = NewPeerKeys(crypt_keys)

	// memclr keys
	for i := range crypt_keys {
		crypt_keys[i] = 0
	}

	// authenticate and wire to pktkit via the adapter
	if p.o.adapter == nil {
		return errors.New("no adapter configured")
	}
	peerCfg, err := p.o.adapter.onPeerAuthenticated(p, auth_user, auth_pass, peer_info_map)
	if err != nil {
		return err
	}

	switch p.opts.DevType {
	case "tap":
		p.layer = 2
	case "tun":
		p.layer = 3
	}

	// use bufio to read from tls stream starting here
	reader := bufio.NewReader(p.tlsConn)

	for {
		buf, err := reader.ReadBytes(0)
		if err != nil {
			return err
		}

		if buf[len(buf)-1] == 0 {
			buf = buf[:len(buf)-1]
		}
		buf_s := string(buf)

		if buf_s == "PUSH_REQUEST" {
			var str string
			if p.opts.DevType == "tap" {
				str = "PUSH_REPLY,ping 10,comp-lzo no,topology net30,ifconfig " + peerCfg.IP.String() + " " + peerCfg.Mask.String()
			} else {
				str = "PUSH_REPLY,ping 10,comp-lzo no,topology net30,ifconfig " + peerCfg.IP.String() + " " + peerCfg.Gateway.String()
			}
			p.tlsConn.Write([]byte(str + "\x00"))
			continue
		}

		log.Printf("[ovpn] Debug - read data on SSL stream %d bytes\n%s\n%s", len(buf), hex.Dump(buf), base64.StdEncoding.EncodeToString(buf))
	}
}

func (p *Peer) readControlString() (string, error) {
	// control string is a uint16 length followed by NULL-terminated string
	var l uint16
	err := binary.Read(p.tlsConn, binary.BigEndian, &l)
	if err != nil {
		return "", err
	}

	if l == 0 {
		return "", errors.New("empty control string")
	}

	str_data := make([]byte, l)
	_, err = io.ReadFull(p.tlsConn, str_data)
	if err != nil {
		return "", err
	}

	if str_data[len(str_data)-1] != 0 {
		return "", errors.New("error reading control string: not NUL-terminated")
	}

	return string(str_data[:len(str_data)-1]), nil
}

func writeControlStringBuf(buf *bytes.Buffer, s string) {
	binary.Write(buf, binary.BigEndian, uint16(len(s)+1))
	buf.WriteString(s)
	buf.WriteByte(0)
}
