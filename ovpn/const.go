package ovpn

type PacketType byte
type CipherCryptoAlg uint8
type CipherBlockMethod uint8

//go:generate stringer -type=PacketType,CipherCryptoAlg,CipherBlockMethod -output stringer.go

const (
	P_CONTROL_HARD_RESET_CLIENT_V1 PacketType = 1 // initial key from client, forget previous state
	P_CONTROL_HARD_RESET_SERVER_V1 PacketType = 2 // initial key from server, forget previous state
	P_CONTROL_SOFT_RESET_V1        PacketType = 3 // new key, graceful transition from old to new key
	P_CONTROL_V1                   PacketType = 4 // control channel packet (usually TLS ciphertext)
	P_ACK_V1                       PacketType = 5 // acknowledgement for packets received
	P_DATA_V1                      PacketType = 6 // data channel packet
	P_DATA_V2                      PacketType = 9 // data channel packet with peer-id
	P_CONTROL_HARD_RESET_CLIENT_V2 PacketType = 7 // initial key from client, forget previous state
	P_CONTROL_HARD_RESET_SERVER_V2 PacketType = 8 // initial key from server, forget previous state
)

const (
	KEY_EXPANSION_ID = "OpenVPN" // Used in the TLS PRF function
	P_KEY_ID_MASK    = 0x07      // packet opcode (high 5 bits) and key-id (low 3 bits) are combined in one byte
	P_OPCODE_SHIFT   = 3

	CONTROL_SEND_ACK_MAX = 4

	TLS_RELIABLE_N_SEND_BUFFERS = 4
	TLS_RELIABLE_N_REC_BUFFERS  = 8

	PUBLIC_NETWORK_MTU      = 1500
	MAX_CONTROL_HEADER_SIZE = 38
	CONTROL_CHANNEL_MTU     = PUBLIC_NETWORK_MTU - MAX_CONTROL_HEADER_SIZE

	KEY_METHOD_MASK = 0x0f

	// this string is used to announce PIA control payload in P_CONTROL_HARD_RESET_CLIENT_V2
	PIA_CONTROL_PREFIX = `53eo0rk92gxic98p1asgl5auh59r1vp4lmry1e3chzi100qntd`
)

const (
	AES CipherCryptoAlg = 1

	CBC CipherBlockMethod = 1
	GCM CipherBlockMethod = 2
)

var (
	OPENVPN_PING = []byte{
		0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
		0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
	}
)
